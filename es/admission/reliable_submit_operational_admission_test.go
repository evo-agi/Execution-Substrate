package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	egscontract "execution-substrate/egs/contract"

	"execution-substrate/es/admission/internal/admissionstate"
	"execution-substrate/es/admission/internal/reliablesubmit"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// These fixtures explicitly commission local proof Services. There is no
// production commissioning caller or installed policy-epoch agreement here.
// Every proof Service has its own synthetic EGS, which signs and serves the
// trust model that Service was commissioned with unless a test changes it.
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

type operationalAdmissionRowState struct {
	Present    bool
	Generation uint64
	Digest     [32]byte
	State      int
}

func operationalAdmissionRowAt(t *testing.T, f *operationalFixture) operationalAdmissionRowState {
	t.Helper()
	var row operationalAdmissionRowState
	var generation int64
	var digest []byte
	err := f.db.QueryRow("SELECT generation, admission_digest, state FROM reliable_submit_operational_admission").
		Scan(&generation, &digest, &row.State)
	if err == sql.ErrNoRows {
		return row
	}
	if err != nil || len(digest) != 32 || generation <= 0 {
		t.Fatalf("admission row: generation=%d digest=%d err=%v", generation, len(digest), err)
	}
	row.Present, row.Generation = true, uint64(generation)
	copy(row.Digest[:], digest)
	return row
}

// operationalResultText prints the value-free parts of a result; the result
// itself formats as a redaction.
func operationalResultText(r operationalHandoffResult) string {
	return fmt.Sprintf("kind=%d reason=%d operation=%d write=%d run=%t receipt=%t", r.kind, r.reason, r.operation, r.write,
		r.run != "", r.receipt.Valid())
}

// operationalInstalledView returns the view the admission state of the
// Service holds, whether or not it may be used. Inspect exists for tests; the
// guard pins that no production code references it.
func operationalInstalledView(s *Service) admissionstate.View {
	return s.operational.Inspect(s).View
}

// operationalViewContent returns a copy of the content a view enforces.
func operationalViewContent(view admissionstate.View) admissionstate.Content {
	return admissionstate.Content{Trust: view.Trust(), Verifier: view.Verifier(), Policies: view.Policies()}
}

// operationalHooks returns the proof hooks the installed view carries: the
// hooks the Service held when the view was installed.
func operationalHooks(s *Service) *operationalAdmissionProofHooks {
	return operationalProofOf(operationalInstalledView(s))
}

// operationalUncommissionedService is a restarted process before it holds a
// view: the fixture's configuration, a private copy of its trust and verifier,
// and its own synthetic EGS serving whatever configure left in place.
func operationalUncommissionedService(t *testing.T, f *operationalFixture, configure func(*Service)) (*Service, *operationalTrustAuthority) {
	t.Helper()
	trust := snapshotRuntimeTrustModel(*f.service.trustModel)
	old := f.service.provenanceVerifier
	service := &Service{cfg: f.service.cfg, trustModel: &trust, trustModelVerified: true,
		provenanceVerifier: &ed25519Verifier{algorithm: old.algorithm, keyID: old.keyID,
			publicKey: bytes.Clone(old.publicKey)},
		// The ordinary resolver's dependencies, so it can also take a fresh delivery.
		arsClient: f.service.arsClient, nomadClient: f.service.nomadClient,
		workloadZoneVaultConfigRef: f.service.workloadZoneVaultConfigRef}
	service.trustModelOwner = service
	service.operational = admissionstate.New(service)
	if configure != nil {
		configure(service)
	}
	var egs *operationalTrustAuthority
	if service.trustModel != nil {
		egs = attachOperationalTrustAuthority(t, service, *service.trustModel)
	}
	return service, egs
}

// operationalProofServiceWithEGS commissions a second Service on the fixture's
// domain as a restarted process would. Content equal to the stored row joins
// its generation. Different content advances the domain from the stored
// generation, which fences every Service that still holds the old token,
// f.service included.
func operationalProofServiceWithEGS(t *testing.T, f *operationalFixture, configure func(*Service)) (*Service, *operationalTrustAuthority) {
	t.Helper()
	ctx := context.Background()
	service, egs := operationalUncommissionedService(t, f, configure)
	_, digest, ok := service.operationalAdmissionContent()
	if !ok {
		t.Fatal("proof Service content cannot be commissioned")
	}
	stored := operationalAdmissionRowAt(t, f)
	var err error
	if stored.Present && stored.State == 1 && stored.Digest == digest {
		err = service.commissionOperationalAdmission(ctx, f.domain)
	} else {
		err = service.advanceOperationalAdmission(ctx, f.domain, stored.Generation)
	}
	if err != nil {
		t.Fatalf("commission selected synthetic policy: %v", err)
	}
	after := operationalAdmissionRowAt(t, f)
	if after.State != 1 || after.Digest != digest || !operationalInstalledView(service).Token().Names(f.domain.realm.installation, f.domain.realm.epoch, digest) {
		t.Fatalf("proof Service does not hold the stored admission: row=%+v", after)
	}
	return service, egs
}

func operationalProofService(t *testing.T, f *operationalFixture, configure func(*Service)) *Service {
	t.Helper()
	service, _ := operationalProofServiceWithEGS(t, f, configure)
	return service
}

// assertOperationalRefusal is assertOperationalNoFurtherEffect plus the exact
// value-free reason.
func assertOperationalRefusal(t *testing.T, f *operationalFixture, before operationalPrestageState,
	out operationalHandoffResult, reason reliablesubmit.OperationalReason) {
	t.Helper()
	assertOperationalNoFurtherEffect(t, f, before, out)
	if out.reason != reason {
		t.Fatalf("refusal reason=%d, want %d: %s", out.reason, reason, operationalResultText(out))
	}
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
		assertOperationalRefusal(t, f, before, out, reliablesubmit.OperationalUnavailable)
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
		assertOperationalRefusal(t, f, before, out, reliablesubmit.OperationalDenied)
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
		assertOperationalRefusal(t, f, before, out, reliablesubmit.OperationalDenied)
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
		verifier := operationalInstalledView(service).Verifier()
		if err := evidencev1.Verify(record, verifier.KeyID, verifier.Algorithm, verifier.PublicKey); err != nil {
			t.Fatalf("revoked signer signature precondition: %v", err)
		}
		before := operationalPrestageStateAt(t, f)
		out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		assertOperationalRefusal(t, f, before, out, reliablesubmit.OperationalDenied)
	})
	// A first delivery that ordinary resolution refuses stores nothing and
	// answers OperationalUnavailable whatever the cause. OperationalDenied is
	// the answer of the re-judgment of a retained original only.
	t.Run("fresh ordinary policy denial", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		configureConfiguredStaticScriptLiteralDenyService(f.service, "policy-fixture-ok")
		out := f.submit()
		state := operationalPrestageStateAt(t, f)
		if out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			out.run != "" || out.receipt.Valid() || state.Claims != 0 || state.Posts != 0 {
			t.Fatalf("ordinary fresh denial: %s state=%+v", operationalResultText(out), state)
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
		if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable ||
			out.reason != reliablesubmit.OperationalUnavailable || out.run != "" || out.receipt.Valid() ||
			state.Claims != 0 || state.Posts != 0 {
			t.Fatalf("fresh ordinary revocation: %s state=%+v", operationalResultText(out), state)
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
	if original.resolved.provenanceRecord != f.expectedEvidence ||
		!bytes.Contains(original.wire, []byte("operational_local_v2")) ||
		!bytes.Contains(original.wire, []byte(f.expectedEvidence)) {
		t.Fatal("full signed evidence was not retained in v2 leaf")
	}
	verified, err := verifyOperationalOriginal(original.wire, f.domain.keys, f.domain.realm)
	if err != nil || verified.resolved.provenanceRecord != f.expectedEvidence {
		t.Fatalf("v2 exact reader: %v", err)
	}
	// A view admits nothing before its first confirmation.
	if reason := f.service.qualifyOperationalRetained(context.Background(), verified, f.domain.realm); reason != reliablesubmit.OperationalUnavailable {
		t.Fatalf("unconfirmed view judged a retained input: %d", reason)
	}
	f.confirm()
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
	// The original is authenticated, so a seal the current verifier refuses is
	// a refusal by the current content, not damaged custody.
	if reason := f.service.qualifyOperationalRetained(context.Background(), mutant, f.domain.realm); reason != reliablesubmit.OperationalDenied {
		t.Fatalf("signature mutant reason=%d", reason)
	}
	verifier := operationalInstalledView(f.service).Verifier()
	resign := func(record *evidencev1.ArtifactEvidence) string {
		t.Helper()
		canonical, err := record.Claims.CanonicalBytes()
		if err != nil {
			t.Fatalf("synthetic contradiction claims: %v", err)
		}
		record.Seal = evidencev1.NewSeal(canonical, verifier.KeyID, verifier.Algorithm,
			base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(f.signerPrivateKey), canonical)))
		if err := record.Validate(); err != nil {
			t.Fatalf("synthetic contradiction is not a valid record: %v", err)
		}
		if err := evidencev1.Verify(*record, verifier.KeyID, verifier.Algorithm, verifier.PublicKey); err != nil {
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
	if wire, err := encodeOperationalOriginal(original.delivery, original.resolved, original.assessment,
		f.domain.keys, f.domain.realm); err != nil || !bytes.Equal(wire, original.wire) {
		t.Fatalf("control: the matching original does not encode to its own bytes: %v", err)
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
			// The encoder refuses the same contradiction before custody can
			// hold it. The record itself decodes, so only its association
			// with the plan and the material can be what fails.
			if _, err := decodeOperationalEvidence(candidate.resolved.provenanceRecord); err != nil {
				t.Fatalf("control: the mismatched record does not decode: %v", err)
			}
			if wire, err := encodeOperationalOriginal(candidate.delivery, candidate.resolved, candidate.assessment,
				f.domain.keys, f.domain.realm); err == nil {
				t.Fatalf("validly signed but mismatched evidence was encoded (%d bytes)", len(wire))
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
			if err := evidencev1.Verify(signed, verifier.KeyID, verifier.Algorithm, verifier.PublicKey); err != nil {
				t.Fatalf("unchanged retained signature precondition: %v", err)
			}
			if operationalEvidenceMatchesOriginal(signed, candidate, f.domain.realm) {
				t.Fatal("frozen contradiction did not isolate association")
			}
			if reason := f.service.qualifyOperationalRetained(context.Background(), candidate, f.domain.realm); reason != reliablesubmit.OperationalIntegrity {
				t.Fatalf("contradictory frozen input reason=%d", reason)
			}
			if wire, err := encodeOperationalOriginal(candidate.delivery, candidate.resolved, candidate.assessment,
				f.domain.keys, f.domain.realm); err == nil {
				t.Fatalf("an original that contradicts its evidence was encoded (%d bytes)", len(wire))
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
	ctx := context.Background()
	// refused requires that neither store operation accepts this Service: a
	// candidate whose content equals the row would otherwise join it, and any
	// other content would otherwise advance it.
	refused := func(t *testing.T, f *operationalFixture, s *Service, what string) {
		t.Helper()
		before := operationalAdmissionRowAt(t, f)
		// A copied Service is not the owner of the state its handle names, so
		// it is shown nothing. Commissioned asks no owner and sees the state
		// the copy shares with its original.
		held, commissioned := operationalInstalledView(s), s.operational.Commissioned()
		if err := s.commissionOperationalAdmission(ctx, f.domain); err == nil {
			t.Fatalf("%s: commission accepted", what)
		}
		if err := s.advanceOperationalAdmission(ctx, f.domain, before.Generation); err == nil {
			t.Fatalf("%s: advance accepted", what)
		}
		if after := operationalAdmissionRowAt(t, f); after != before || operationalInstalledView(s) != held ||
			s.operational.Commissioned() != commissioned {
			t.Fatalf("%s: a refused commission changed the domain or the view: before=%+v after=%+v", what, before, after)
		}
	}
	t.Run("view is a private copy bound to owner, installation and epoch", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		realm := f.domain.realm
		view := operationalInstalledView(f.service)
		row := operationalAdmissionRowAt(t, f)
		digest, ok := admissionstate.Digest(operationalViewContent(view))
		if !ok || !row.Present || row.Generation != 1 || row.State != 1 || row.Digest != digest ||
			!view.Token().Names(realm.installation, realm.epoch, digest) {
			t.Fatalf("fixture commission is not generation 1 of the view's own content: %+v", row)
		}
		original := operationalV2Original(t, f)
		initial := operationalViewContent(view)
		// In-place changes reach a view that shares a backing array; an append
		// alone would not.
		f.service.trustModel.SignerPolicy.AllowedSigners[0] = "replaced-after-commission"
		f.service.trustModel.ArtifactPolicy.RevokedArtifacts = append(f.service.trustModel.ArtifactPolicy.RevokedArtifacts,
			original.resolved.plan.artifactDigest)
		f.service.provenanceVerifier.publicKey[0] ^= 0xff
		after, ok := admissionstate.Digest(operationalViewContent(view))
		if !ok || after != digest || !reflect.DeepEqual(initial, operationalViewContent(view)) || operationalAdmissionRowAt(t, f) != row {
			t.Fatal("commissioned trust or verifier aliased caller input")
		}
		// What the view hands out is a copy as well: a write to it reaches
		// neither the view nor a later copy.
		handed := operationalViewContent(view)
		handed.Trust.SignerPolicy.AllowedSigners[0] = "replaced-in-a-copy"
		handed.Trust.ArtifactPolicy.RevokedArtifacts = append(handed.Trust.ArtifactPolicy.RevokedArtifacts, original.resolved.plan.artifactDigest)
		handed.Verifier.PublicKey[0] ^= 0xff
		handed.Policies[0].ID = "replaced-in-a-copy"
		if after, ok := admissionstate.Digest(operationalViewContent(view)); !ok || after != digest ||
			!reflect.DeepEqual(initial, operationalViewContent(view)) {
			t.Fatal("a copy handed out by the view aliased the view")
		}
		f.confirm()
		if reason := f.service.qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalReasonNone {
			t.Fatalf("a change to the Service's own lists changed the view's decision: %d", reason)
		}
		refused(t, f, f.service, "Service that already holds a view")
		// A Service that holds the handle of this confirmed state is not its
		// owner and is shown nothing. The control below is the same question
		// asked by the owner.
		foreign := &Service{operational: f.service.operational}
		if _, ok := foreign.currentOperationalAdmission(realm); ok || operationalInstalledView(foreign).Installed() {
			t.Fatal("foreign Service borrowed authority")
		}
		otherEpoch, otherInstallation := realm, realm
		otherEpoch.epoch++
		otherInstallation.installation[0] ^= 1
		if current, ok := f.service.currentOperationalAdmission(realm); !ok || current != view {
			t.Fatal("confirmed view is not current for its own realm")
		}
		if _, ok := f.service.currentOperationalAdmission(otherEpoch); ok {
			t.Fatal("old authority crossed epoch")
		}
		if _, ok := f.service.currentOperationalAdmission(otherInstallation); ok {
			t.Fatal("authority crossed installation")
		}
		if err := f.service.Initialize(ctx); err == nil || f.egs.count() != 1 {
			t.Fatalf("Initialize replaced commissioned trust: err=%v trust requests=%d", err, f.egs.count())
		}
	})
	t.Run("the view enforces normalized lists", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		original := operationalV2Original(t, f)
		padded, egs := operationalProofServiceWithEGS(t, f, func(s *Service) {
			s.trustModel.SignerPolicy.AllowedSigners[0] = "  " + s.trustModel.SignerPolicy.AllowedSigners[0] + "\t"
		})
		if row := operationalAdmissionRowAt(t, f); row.Generation != 1 ||
			operationalInstalledView(padded).Token() != operationalInstalledView(f.service).Token() {
			t.Fatalf("equal normalized content did not join the stored generation: %+v", row)
		}
		padded.confirmOperationalAdmission(ctx)
		if reason := padded.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalReasonNone || egs.count() != 1 {
			t.Fatalf("view did not enforce the normalized list it was hashed over: reason=%d requests=%d", reason, egs.count())
		}
	})
	t.Run("copied, oversized and unsupported Services gain nothing", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		precommission, _ := operationalUncommissionedService(t, f, nil)
		// An exact struct copy of the unlocked precommission Service. Reflection
		// keeps vet's copylocks check enabled for every ordinary assignment.
		copied := new(Service)
		reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(precommission).Elem())
		if copied.trustModelOwner != precommission || copied.trustModel != precommission.trustModel ||
			!copied.trustModelVerified || copied.provenanceVerifier != precommission.provenanceVerifier {
			t.Fatal("copy fixture did not reproduce the precommission Service")
		}
		refused(t, f, copied, "copied precommission Service")
		// The same with content of its own. The copy above holds the stored
		// content, so a store write by it would change nothing; this one would
		// replace the row and fence every other process if its ownership were
		// checked only after the write.
		changed := func(s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				"sha256:"+strings.Repeat("c", 64))
		}
		other, _ := operationalUncommissionedService(t, f, changed)
		if _, digest, ok := other.operationalAdmissionContent(); !ok || digest == operationalAdmissionRowAt(t, f).Digest {
			t.Fatal("control: the changed candidate does not carry content of its own")
		}
		copiedOther := new(Service)
		reflect.ValueOf(copiedOther).Elem().Set(reflect.ValueOf(other).Elem())
		refused(t, f, copiedOther, "copied Service with content of its own")
		// A copy that was given an admission state of its own owns that state,
		// so the state does not refuse it. It is still not the Service that
		// loaded and verified the trust model it carries, and that is checked
		// before the store write.
		copiedWithState := new(Service)
		reflect.ValueOf(copiedWithState).Elem().Set(reflect.ValueOf(other).Elem())
		copiedWithState.operational = admissionstate.New(copiedWithState)
		if !copiedWithState.operational.Installable(copiedWithState) || copiedWithState.trustModelOwner != other {
			t.Fatal("control: the copy does not own an open state, or owns its trust model")
		}
		refused(t, f, copiedWithState, "copied Service with content and an admission state of its own")
		oversized, _ := operationalUncommissionedService(t, f, func(s *Service) {
			for i := 0; i < 3600; i++ {
				s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
					fmt.Sprintf("sha256:%064x", i))
			}
		})
		refused(t, f, oversized, "oversized trust representation")
		for name, configure := range map[string]func(*Service){
			"no trust":         func(s *Service) { s.trustModel = nil },
			"unverified trust": func(s *Service) { s.trustModelVerified = false },
			"unverified trust with content of its own": func(s *Service) {
				changed(s)
				s.trustModelVerified = false
			},
			"invalid trust":                  func(s *Service) { s.trustModel.SignerPolicy.AllowedSigners = []string{"twice", "twice"} },
			"no verifier":                    func(s *Service) { s.provenanceVerifier = nil },
			"short verifier key":             func(s *Service) { s.provenanceVerifier.publicKey = s.provenanceVerifier.publicKey[:31] },
			"unsupported verifier algorithm": func(s *Service) { s.provenanceVerifier.algorithm = "ed448" },
			"blank verifier key id":          func(s *Service) { s.provenanceVerifier.keyID = " \t" },
			// Consistently configured, so only the configuration's own validity refuses it.
			"invalid configuration": func(s *Service) {
				configureConfiguredStaticScriptLiteralDenyService(s, "control\x00character")
			},
			"unsupported evaluator": func(s *Service) { s.admissionPolicyEvaluator = &rejectAllPolicy{} },
			"nested evaluator": func(s *Service) {
				s.admissionPolicyEvaluator = admissionPolicySet{policies: []AdmissionPolicyEvaluator{admissionPolicySet{policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{}}}}}
			},
			"mismatched built-in": func(s *Service) {
				configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
				s.admissionPolicyEvaluator = defaultAdmissionPolicyEvaluator()
			},
			// Audit R2: the same shape as configuration with a different entry.
			"injected entries differ from configuration": func(s *Service) {
				injected := &Service{}
				configureConfiguredStaticScriptLiteralDenyService(injected, "injected-literal")
				configureConfiguredStaticScriptLiteralDenyService(s, "configured-literal")
				s.admissionPolicyEvaluator = injected.admissionPolicyEvaluator
			},
		} {
			t.Run(name, func(t *testing.T) {
				s, _ := operationalUncommissionedService(t, f, configure)
				refused(t, f, s, name)
			})
		}
		// Controls: the unchanged candidate joins, and a consistently configured
		// one advances, so each refusal above is the content check's.
		if err := precommission.commissionOperationalAdmission(ctx, f.domain); err != nil ||
			operationalInstalledView(precommission).Token() != operationalInstalledView(f.service).Token() {
			t.Fatalf("control: unchanged precommission Service did not join: %v", err)
		}
		consistent, _ := operationalUncommissionedService(t, f, func(s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "configured-literal")
		})
		if err := consistent.advanceOperationalAdmission(ctx, f.domain, 1); err != nil || operationalAdmissionRowAt(t, f).Generation != 2 {
			t.Fatalf("control: consistently configured Service did not advance: %v", err)
		}
		// The two Services that hold generation 1 cannot take the domain back.
		refused(t, f, f.service, "fixture Service after a later generation")
		refused(t, f, precommission, "joined Service after a later generation")
	})
	t.Run("configured entries are private copies", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		configured := operationalProofService(t, f, func(s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "immutable-marker")
		})
		view := operationalInstalledView(configured)
		digest, ok := admissionstate.Digest(operationalViewContent(view))
		selected := view.Policies()[1]
		configured.cfg.AdmissionPolicy.ConfiguredStaticScriptLiteralDeny.Entries[0].Literal = "mutated-config"
		outer := configured.admissionPolicyEvaluator.(admissionPolicySet)
		aliased := outer.policies[1].(configuredStaticScriptLiteralDenyPolicy)
		aliased.entries[0].literal = "mutated-evaluator"
		// The copy the view handed out is the test's own.
		selected.Entries[0].Literal = "mutated-copy"
		after, afterOK := admissionstate.Digest(operationalViewContent(view))
		if !ok || !afterOK || after != digest || view.Policies()[1].Entries[0].Literal != "immutable-marker" {
			t.Fatal("commissioned policy entries aliased config, the ordinary evaluator or a copy handed out")
		}
		// The set the view enforces is built from that content.
		enforced, built := operationalPolicySet(view.Policies())
		if !built || len(enforced.policies) != 2 ||
			enforced.policies[1].(configuredStaticScriptLiteralDenyPolicy).entries[0].literal != "immutable-marker" {
			t.Fatal("the enforced set does not hold the commissioned entry")
		}
	})
	// The digest decides whether a restarted process joins the stored generation
	// or has to advance it. Each candidate differs from the stored content in
	// exactly one field. A digest that left that field out would let the
	// candidate join, unfenced, with content of its own.
	t.Run("content that differs in one field is other content", func(t *testing.T) {
		entries := func(pairs ...[2]string) func(*Service) {
			return func(s *Service) {
				configureConfiguredStaticScriptLiteralDenyService(s, pairs[0][1])
				policy := s.cfg.AdmissionPolicy.ConfiguredStaticScriptLiteralDeny
				first := policy.Entries[0]
				policy.Entries = policy.Entries[:0]
				for _, pair := range pairs {
					entry := first
					entry.ID, entry.Literal = pair[0], pair[1]
					policy.Entries = append(policy.Entries, entry)
				}
				s.admissionPolicyEvaluator = admissionPolicyEvaluatorFromConfig(s.cfg.AdmissionPolicy)
			}
		}
		for _, tc := range []struct {
			name              string
			stored, candidate func(*Service)
		}{
			{"the literal of a configured entry", entries([2]string{"marker", "literal-one"}), entries([2]string{"marker", "literal-two"})},
			{"the id of a configured entry", entries([2]string{"marker-one", "literal"}), entries([2]string{"marker-two", "literal"})},
			{"one more configured entry", entries([2]string{"marker", "literal"}),
				entries([2]string{"marker", "literal"}, [2]string{"second", "other"})},
			{"the literal of the second configured entry", entries([2]string{"marker", "literal"}, [2]string{"second", "one"}),
				entries([2]string{"marker", "literal"}, [2]string{"second", "two"})},
			{"the verifier key id", nil, func(s *Service) { s.provenanceVerifier.keyID += "-next" }},
			{"the verifier key", nil, func(s *Service) { s.provenanceVerifier.publicKey[0] ^= 1 }},
			{"one more allowed signer", nil, func(s *Service) {
				s.trustModel.SignerPolicy.AllowedSigners = append(s.trustModel.SignerPolicy.AllowedSigners, "one-more-signer")
			}},
			{"one more revoked signer", nil, func(s *Service) {
				s.trustModel.SignerPolicy.RevokedSigners = append(s.trustModel.SignerPolicy.RevokedSigners, "one-more-revoked-signer")
			}},
			{"one more revoked artifact", nil, func(s *Service) {
				s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
					"sha256:"+strings.Repeat("f", 64))
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := makeOperationalFixture(t, "")
				if tc.stored != nil {
					operationalProofService(t, f, tc.stored)
				}
				row := operationalAdmissionRowAt(t, f)
				candidate, _ := operationalUncommissionedService(t, f, tc.candidate)
				_, digest, ok := candidate.operationalAdmissionContent()
				if !ok {
					t.Fatal("control: the candidate's content cannot be commissioned at all")
				}
				if digest == row.Digest {
					t.Fatal("content that differs in this field carries the stored digest")
				}
				if err := candidate.commissionOperationalAdmission(ctx, f.domain); err == nil || operationalInstalledView(candidate).Installed() ||
					operationalAdmissionRowAt(t, f) != row {
					t.Fatalf("content that differs in this field joined the stored generation: err=%v", err)
				}
				if err := candidate.advanceOperationalAdmission(ctx, f.domain, row.Generation); err != nil {
					t.Fatalf("other content could not advance the domain: %v", err)
				}
				next := operationalAdmissionRowAt(t, f)
				if next.Generation != row.Generation+1 || next.State != 1 || next.Digest != digest {
					t.Fatalf("the advance did not store the candidate's content: before=%+v after=%+v", row, next)
				}
				// Control: the comparison is by content, so a second process with
				// the candidate's content joins the candidate's generation.
				twin, _ := operationalUncommissionedService(t, f, tc.candidate)
				if err := twin.commissionOperationalAdmission(ctx, f.domain); err != nil ||
					operationalInstalledView(twin).Token() != operationalInstalledView(candidate).Token() || operationalAdmissionRowAt(t, f) != next {
					t.Fatalf("control: equal content did not join its own generation: %v", err)
				}
			})
		}
	})
	// No comma in this name: the fixture's staging path is derived from it, and
	// scope-3 custody refuses a path that holds one.
	t.Run("withdrawal is monotonic and durable for the whole domain", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		realm := f.domain.realm
		joined, _ := operationalProofServiceWithEGS(t, f, nil)
		f.confirm()
		joined.confirmOperationalAdmission(ctx)
		if _, ok := joined.currentOperationalAdmission(realm); !ok {
			t.Fatal("control: joined Service is not current before the withdrawal")
		}
		if (&Service{}).withdrawOperationalEffects(ctx, f.domain) {
			t.Fatal("a Service without a view withdrew the domain")
		}
		if row := operationalAdmissionRowAt(t, f); row.State != 1 || row.Generation != 1 {
			t.Fatalf("refused withdrawal changed the row: %+v", row)
		}
		if !f.service.withdrawOperationalEffects(ctx, f.domain) || !f.service.withdrawOperationalEffects(ctx, f.reopen()) {
			t.Fatal("withdrawal did not remain monotonic")
		}
		if row := operationalAdmissionRowAt(t, f); row.State != 2 || row.Generation != 1 {
			t.Fatalf("withdrawal is not durable at the same generation: %+v", row)
		}
		if _, ok := f.service.currentOperationalAdmission(realm); ok {
			t.Fatal("withdrawn authority is still current")
		}
		refused(t, f, f.service, "withdrawn Service")
		// The domain is stopped for a Service that never withdrew.
		seeded := operationalPrestageStateAt(t, f)
		out := joined.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			out.run != "" || state != seeded || state.Claims != 0 {
			t.Fatalf("a withdrawn domain admitted a fresh delivery: %s state=%+v", operationalResultText(out), state)
		}
		// Equal content cannot enable it again; only an advance to new content can.
		same, _ := operationalUncommissionedService(t, f, nil)
		refused(t, f, same, "equal content on a withdrawn domain")
		next := operationalProofService(t, f, func(s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				"sha256:"+strings.Repeat("e", 64))
		})
		if row := operationalAdmissionRowAt(t, f); row.State != 1 || row.Generation != 2 {
			t.Fatalf("advance after withdrawal did not enable the next generation: %+v", row)
		}
		// The process that withdrew stays stopped; the new generation works.
		f.service.confirmOperationalAdmission(ctx)
		if _, ok := f.service.currentOperationalAdmission(realm); ok {
			t.Fatal("withdrawn authority was reenabled")
		}
		if stopped := f.submit(); stopped.kind != operationalUnavailable || operationalPrestageStateAt(t, f).Claims != 0 {
			t.Fatalf("withdrawn Service acted after the domain was enabled again: %s", operationalResultText(stopped))
		}
		// A Service that holds a view cannot move the row, even when it names
		// the stored generation and its own content differs from the row's:
		// the process that withdrew, and one that only joined generation 1.
		refused(t, f, f.service, "withdrawn Service on a later generation")
		refused(t, f, joined, "Service that holds the view of an earlier generation")
		if done := next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw); done.kind != operationalAccepted ||
			operationalPrestageStateAt(t, f).Posts != 1 {
			t.Fatalf("new generation after a withdrawal: %s state=%+v", operationalResultText(done), operationalPrestageStateAt(t, f))
		}
	})
	t.Run("a withdrawal the store does not confirm is reported as unconfirmed", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		f.confirm()
		// The store refuses every write under an ended context, so this
		// withdrawal reaches the process and not the domain.
		ended, cancel := context.WithCancel(ctx)
		cancel()
		if f.service.withdrawOperationalEffects(ended, f.domain) {
			t.Fatal("a withdrawal the store did not perform was reported as confirmed")
		}
		if row := operationalAdmissionRowAt(t, f); row.State != 1 || row.Generation != 1 {
			t.Fatalf("control: the store performed the withdrawal: %+v", row)
		}
		if _, ok := f.service.currentOperationalAdmission(f.domain.realm); ok {
			t.Fatal("the process is not stopped after an unconfirmed withdrawal")
		}
		// The call may be repeated, and the repeat is what stops the domain.
		if !f.service.withdrawOperationalEffects(ctx, f.domain) {
			t.Fatal("the repeated withdrawal was not confirmed")
		}
		if row := operationalAdmissionRowAt(t, f); row.State != 2 || row.Generation != 1 {
			t.Fatalf("the repeated withdrawal is not durable: %+v", row)
		}
	})
	t.Run("Initialize fetch cannot overwrite racing commission", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		s, egs := operationalUncommissionedService(t, f, nil)
		trust := snapshotRuntimeTrustModel(*s.trustModel)
		egs.serve(egscontract.RuntimeTrustPolicy{SignerPolicy: egscontract.SignerPolicy{AllowedSigners: []string{"other-signer"}}})
		entered, release := make(chan struct{}), make(chan struct{})
		egs.observe(func() {
			close(entered)
			<-release
		})
		result := make(chan error, 1)
		go func() { result <- s.Initialize(ctx) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Initialize did not enter trust fetch")
		}
		if err := s.commissionOperationalAdmission(ctx, f.domain); err != nil {
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
	t.Run("trust load during the store write leaves the Service closed", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		s, egs := operationalUncommissionedService(t, f, nil)
		egs.serve(egscontract.RuntimeTrustPolicy{SignerPolicy: egscontract.SignerPolicy{AllowedSigners: []string{"other-signer"}}})
		loaded := false
		err := s.installOperationalAdmission(ctx, f.domain, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
			if err := s.Initialize(ctx); err != nil {
				t.Fatalf("trust load before a view exists: %v", err)
			}
			loaded = true
			return f.domain.custody.CommissionOperationalAdmission(ctx, f.domain.realm.installation, f.domain.realm.epoch, digest)
		})
		if !loaded || err == nil || operationalInstalledView(s).Installed() {
			t.Fatalf("a view was installed over a trust model the store write did not cover: loaded=%t err=%v", loaded, err)
		}
		s.confirmOperationalAdmission(ctx)
		if _, ok := s.currentOperationalAdmission(f.domain.realm); ok {
			t.Fatal("Service without a view is current")
		}
		if row := operationalAdmissionRowAt(t, f); row.Generation != 1 || row.State != 1 {
			t.Fatalf("raced commission changed the domain: %+v", row)
		}
	})
	// installOperationalAdmission samples the Service, lets the store write run
	// without Service.mu, and installs under the lock only what is still true.
	// Each case changes one sampled fact from inside the store write.
	t.Run("what changes during the store write is seen before a view is installed", func(t *testing.T) {
		commission := func(f *operationalFixture, digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
			return f.domain.custody.CommissionOperationalAdmission(ctx, f.domain.realm.installation, f.domain.realm.epoch, digest)
		}
		t.Run("the same Service is commissioned by another caller", func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			s, _ := operationalUncommissionedService(t, f, nil)
			var first admissionstate.View
			err := s.installOperationalAdmission(ctx, f.domain, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
				if err := s.commissionOperationalAdmission(ctx, f.domain); err != nil {
					t.Fatalf("commission inside the outer store write: %v", err)
				}
				first = operationalInstalledView(s)
				return commission(f, digest)
			})
			if !first.Installed() || err == nil || operationalInstalledView(s) != first {
				t.Fatalf("an installed view was replaced: first installed=%t same=%t err=%v", first.Installed(),
					operationalInstalledView(s) == first, err)
			}
		})
		for name, change := range map[string]func(*Service){
			"the Service no longer owns its trust model": func(s *Service) { s.trustModelOwner = &Service{} },
			"the trust model is no longer verified":      func(s *Service) { s.trustModelVerified = false },
		} {
			t.Run(name, func(t *testing.T) {
				f := makeOperationalFixture(t, "")
				s, _ := operationalUncommissionedService(t, f, nil)
				changed := false
				err := s.installOperationalAdmission(ctx, f.domain, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
					s.mu.Lock()
					change(s)
					s.mu.Unlock()
					changed = true
					return commission(f, digest)
				})
				if !changed || err == nil || operationalInstalledView(s).Installed() {
					t.Fatalf("a view was installed over trust the Service no longer holds: changed=%t err=%v", changed, err)
				}
			})
		}
		t.Run("the store returns a token for other content", func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			// The row is advanced to other content first, so the store can return
			// a real token of this domain that does not name this Service's content.
			other := operationalProofService(t, f, func(s *Service) {
				s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
					"sha256:"+strings.Repeat("d", 64))
			})
			row := operationalAdmissionRowAt(t, f)
			s, _ := operationalUncommissionedService(t, f, nil)
			asked := false
			err := s.installOperationalAdmission(ctx, f.domain, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
				asked = digest != row.Digest
				return operationalInstalledView(other).Token(), nil
			})
			if !asked || err == nil || operationalInstalledView(s).Installed() || operationalAdmissionRowAt(t, f) != row {
				t.Fatalf("a view was installed with a token that does not name its content: asked=%t err=%v", asked, err)
			}
			// Control: the returned token is a real one and names the stored content.
			if !operationalInstalledView(other).Token().Names(f.domain.realm.installation, f.domain.realm.epoch, row.Digest) {
				t.Fatal("control: the returned token does not name the stored content")
			}
		})
	})
	t.Run("a token from one database is refused by another", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		// The second database lives in a nested test so that its installation
		// identity, which the fixture derives from the test name, differs.
		t.Run("other database", func(t *testing.T) {
			other := makeOperationalFixture(t, "")
			if other.domain.realm.installation == f.domain.realm.installation {
				t.Fatal("control: the two databases share an installation identity")
			}
			original := operationalV2Original(t, other)
			foreign := operationalInstalledView(f.service).Token()
			if got := other.domain.custody.EstablishOperational(ctx, original.delivery.refs.claimID, original.assessment.boundPlan,
				other.domain.keys.storage, original.wire, foreign).Disposition(); got == reliablesubmit.OperationalApplied ||
				got == reliablesubmit.OperationalOwnCommitConfirmed {
				t.Fatalf("another database accepted a foreign admission token: %d", got)
			}
			f.confirm()
			out := f.service.handoffOperational(ctx, other.domain, other.domain.caller, other.raw)
			if state := operationalPrestageStateAt(t, other); out.kind != operationalUnavailable ||
				out.reason != reliablesubmit.OperationalUnavailable || state.Claims != 0 || state.Grants != 0 || state.Posts != 0 {
				t.Fatalf("a Service commissioned elsewhere acted on this database: %s state=%+v", operationalResultText(out), state)
			}
			if got := other.domain.custody.EstablishOperational(ctx, original.delivery.refs.claimID, original.assessment.boundPlan,
				other.domain.keys.storage, original.wire, operationalInstalledView(other.service).Token()).Disposition(); got != reliablesubmit.OperationalApplied {
				t.Fatalf("control: the database's own token did not establish: %d", got)
			}
		})
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
		const required = "observed := policyCtx\n\t\tobserved.InvocationArgv = slices.Clone(policyCtx.InvocationArgv)\n\t\tproof.contextObserved(observed)\n\t}\n\tdecision := policy.Evaluate(ctx, policyCtx)"
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
	f.confirm()
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
		operationalHooks(retained.service).contextObserved = func(value AdmissionPolicyContext) {
			copyOfValue := value
			copyOfValue.InvocationArgv = append([]string(nil), value.InvocationArgv...)
			observations = append(observations, copyOfValue)
			value.InvocationArgv[0] = "observer-mutated-copy"
		}
		// A retained continuation has no ARS or resolver dependency. It asks
		// EGS once, only to confirm the trust it was commissioned with.
		retained.service.arsClient = nil
		before := operationalPrestageStateAt(t, retained)
		requests := retained.egs.count()
		out := retained.service.handoffOperational(context.Background(), retained.reopen(), retained.domain.caller, retained.raw)
		if retained.egs.count() != requests+1 {
			t.Fatalf("retained continuation made %d trust requests, want exactly one", retained.egs.count()-requests)
		}
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
			// Each hook runs between writer turns. The withdrawal must be
			// durable there, not only local.
			withdraw := func() {
				reached.Store(true)
				if !f.service.withdrawOperationalEffects(context.Background(), f.domain) {
					t.Error("withdrawal between turns was not confirmed")
				}
			}
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
				out.reason != reliablesubmit.OperationalUnavailable ||
				state.Revision != tc.wantRevision || (state.StageEntries != 0) != tc.wantStage ||
				state.Marker != tc.wantMarker || state.Posts != 0 || operationalAdmissionRowAt(t, f).State != 2 {
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
				f.service.withdrawOperationalEffects(context.Background(), f.domain)
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
		operationalHooks(f.service).evaluated = func(bool) {
			if armed {
				calls++
				// Evaluation 2 is the release qualifier, after COMMIT.
				if calls == 2 && !f.service.withdrawOperationalEffects(context.Background(), f.domain) {
					t.Error("withdrawal at the release qualifier was not confirmed")
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
		if !f.service.withdrawOperationalEffects(context.Background(), f.domain) {
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

// operational_local_v1 is removed. Its bytes, built independently in the layout
// published at 8058561, remain only as negative vectors: scope-3 custody
// refuses them, the reader refuses them, and nothing can compose them.
func TestOperationalV1Removed(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)
	claim, plan, token := original.delivery.refs.claimID, original.assessment.boundPlan, operationalInstalledView(f.service).Token()
	// Control: the same independent builder reproduces the v2 wire, and both
	// layers accept it, so each refusal below is about the v1 layout alone.
	current := operationalVectorWire(t, f, original, f.expectedEvidence)
	if !bytes.Equal(current, original.wire) {
		t.Fatal("control: independent v2 vector differs from the composed original")
	}
	if _, err := reliablesubmit.MatchOperationalOriginal(claim, plan, current); err != nil {
		t.Fatalf("control: scope-3 custody refused v2: %v", err)
	}
	if _, err := verifyOperationalOriginal(current, f.domain.keys, f.domain.realm); err != nil {
		t.Fatalf("control: reader refused v2: %v", err)
	}
	published := operationalVectorWire(t, f, original, "")
	member := operationalVectorObject([]byte("synthetic"), []byte("record"), []byte("owner"))
	sequence := binary.BigEndian.AppendUint16(nil, 1)
	sequence = binary.BigEndian.AppendUint32(sequence, uint32(len(member)))
	sequence = append(sequence, member...)
	for name, wire := range map[string][]byte{
		"published layout with the empty sequence":   published,
		"published layout with a nonempty sequence":  operationalVectorReplaceProvenance(t, published, "operational_local_v1", sequence),
		"v1 literal over the retained evidence leaf": operationalVectorReplaceProvenance(t, original.wire, "operational_local_v1", []byte(f.expectedEvidence)),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(wire, current) {
				t.Fatal("negative vector equals the accepted wire")
			}
			if _, err := reliablesubmit.MatchOperationalOriginal(claim, plan, wire); err == nil {
				t.Fatal("scope-3 custody shape accepted a removed layout")
			}
			if _, err := verifyOperationalOriginal(wire, f.domain.keys, f.domain.realm); err == nil {
				t.Fatal("reader accepted a removed layout")
			}
			before := operationalPrestageStateAt(t, f)
			got := f.domain.custody.EstablishOperational(ctx, claim, plan, f.domain.keys.storage, wire, token)
			if after := operationalPrestageStateAt(t, f); got.Disposition() == reliablesubmit.OperationalApplied ||
				got.Disposition() == reliablesubmit.OperationalOwnCommitConfirmed || after != before || after.Claims != 0 || after.Grants != 0 {
				t.Fatalf("custody stored a removed layout: disposition=%d before=%+v after=%+v", got.Disposition(), before, after)
			}
		})
	}
	t.Run("an empty evidence record cannot be composed", func(t *testing.T) {
		if _, err := encodeOperationalOriginal(original.delivery, original.resolved, original.assessment, f.domain.keys, f.domain.realm); err != nil {
			t.Fatalf("control: the resolved original does not encode: %v", err)
		}
		empty := original.resolved
		empty.provenanceRecord = ""
		if wire, err := encodeOperationalOriginal(original.delivery, empty, original.assessment, f.domain.keys, f.domain.realm); err == nil {
			t.Fatalf("an empty evidence record was encoded (%d bytes)", len(wire))
		}
		if _, err := decodeOperationalEvidence(""); err == nil {
			t.Fatal("an empty evidence record was decoded")
		}
	})
	t.Run("no production source names the removed literal", func(t *testing.T) {
		removed := "operational_local_" + "v1"
		checked := 0
		for _, dir := range []string{".", "internal/reliablesubmit"} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				checked++
				if bytes.Contains(data, []byte(removed)) {
					t.Errorf("%s still names %s", filepath.Join(dir, entry.Name()), removed)
				}
			}
		}
		format, err := os.ReadFile("reliable_submit_operational_format.go")
		if err != nil || checked < 20 || !bytes.Contains(format, []byte("operational_local_"+"v2")) {
			t.Fatalf("control: production sources were not read (%d files, err=%v)", checked, err)
		}
	})
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
	// An independent second resolution of the same request reads the evidence
	// once more and yields the same plan, PB1 material, host and record.
	again, failure := f.service.resolveExecutionForSubmit(testCallerContext(), original.delivery.request)
	if failure != nil {
		t.Fatalf("independent resolution: %s", failure.Code)
	}
	if !reflect.DeepEqual(original.resolved.plan, again.plan) || !reflect.DeepEqual(original.resolved.material, again.material) ||
		!reflect.DeepEqual(original.resolved.host, again.host) || again.provenanceRecord != f.expectedEvidence ||
		evidenceReads.Load() != 2 {
		t.Fatalf("independent resolution differs from the captured one: evidence reads=%d", evidenceReads.Load())
	}
	// The carrier is one string beside them. No value inside the plan, the PB1
	// material or the host holds the record or its signature.
	var signed evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &signed); err != nil || signed.Seal.Signature == "" {
		t.Fatalf("signed evidence fixture: %v", err)
	}
	needles := []string{f.expectedEvidence, signed.Seal.Signature}
	for name, value := range map[string]any{"plan": original.resolved.plan, "PB1 material": original.resolved.material,
		"host": original.resolved.host} {
		if operationalValueCarries(reflect.ValueOf(value), needles, map[uintptr]bool{}) {
			t.Fatalf("provenance carrier entered %s", name)
		}
	}
	if !operationalValueCarries(reflect.ValueOf(original.resolved), needles, map[uintptr]bool{}) {
		t.Fatal("control: the walk did not find the carrier in the resolution that holds it")
	}
	// The resolution carries the record as an immutable string, never as the
	// typed, mutable evidence value.
	typed := reflect.TypeOf(evidencev1.ArtifactEvidence{})
	if operationalTypeHolds(reflect.TypeOf(original.resolved), typed, map[reflect.Type]bool{}) {
		t.Fatal("resolved carrier aliases typed mutable evidence")
	}
	if !operationalTypeHolds(reflect.TypeOf(struct {
		held []*evidencev1.ArtifactEvidence
	}{}), typed, map[reflect.Type]bool{}) {
		t.Fatal("control: the type walk did not find typed evidence where it is held")
	}
	if fmt.Sprintf("%+v", original) != privateExecutionValueRedaction ||
		fmt.Sprintf("%+v", preparedArtifact{provenanceRecord: original.resolved.provenanceRecord}) != privateExecutionValueRedaction {
		t.Fatal("full signed evidence escaped private formatting")
	}
}

// operationalValueCarries reports whether any string or byte slice reachable
// from v contains one of the needles. It reads unexported fields.
func operationalValueCarries(v reflect.Value, needles []string, seen map[uintptr]bool) bool {
	holds := func(text string) bool {
		for _, needle := range needles {
			if strings.Contains(text, needle) {
				return true
			}
		}
		return false
	}
	switch v.Kind() {
	case reflect.String:
		return holds(v.String())
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return false
		}
		if v.Kind() == reflect.Pointer {
			if seen[v.Pointer()] {
				return false
			}
			seen[v.Pointer()] = true
		}
		return operationalValueCarries(v.Elem(), needles, seen)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return holds(string(v.Bytes()))
		}
		for i := 0; i < v.Len(); i++ {
			if operationalValueCarries(v.Index(i), needles, seen) {
				return true
			}
		}
	case reflect.Map:
		for iter := v.MapRange(); iter.Next(); {
			if operationalValueCarries(iter.Key(), needles, seen) || operationalValueCarries(iter.Value(), needles, seen) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if operationalValueCarries(v.Field(i), needles, seen) {
				return true
			}
		}
	}
	return false
}

// operationalTypeHolds reports whether target is reachable from t through
// fields, pointers, slices, arrays and maps.
func operationalTypeHolds(t, target reflect.Type, seen map[reflect.Type]bool) bool {
	if t == target {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return operationalTypeHolds(t.Elem(), target, seen)
	case reflect.Map:
		return operationalTypeHolds(t.Key(), target, seen) || operationalTypeHolds(t.Elem(), target, seen)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if operationalTypeHolds(t.Field(i).Type, target, seen) {
				return true
			}
		}
	}
	return false
}

type admissionCountTransport func(*http.Request) (*http.Response, error)

func (f admissionCountTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A retry after the current admission inputs change is evaluated against the
// newly commissioned authority at the first remaining cut. Denial leaves the
// retained claim exactly where it was. The Service that still holds the old
// generation is fenced and judges nothing. A later generation that allows the
// claim completes it, so a denial before staging neither advances nor poisons
// the claim.
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
				if after := operationalPrestageStateAt(t, f); denied.reason != reliablesubmit.OperationalDenied ||
					after != seeded {
					t.Fatalf("denied retry: result=%+v before=%+v after=%+v", denied, seeded, after)
				}
				f.evaluated.Store(0)
				fenced := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				assertOperationalRefusal(t, f, seeded, fenced, reliablesubmit.OperationalUnavailable)
				if f.evaluated.Load() != 0 {
					t.Fatal("a fenced Service judged the claim under content the domain has replaced")
				}
				allowing := operationalProofService(t, f, nil)
				allowed := allowing.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				if state := operationalPrestageStateAt(t, f); allowed.kind != operationalAccepted || allowed.run == "" ||
					state.Revision != 6 || !state.Marker || state.Posts != 1 || operationalAdmissionRowAt(t, f).Generation != 3 {
					t.Fatalf("allowed retry after denial: %s state=%+v", operationalResultText(allowed), state)
				}
			})
		}
	}
}

// ---- Durable admission generation: helpers ----

// operationalSeedAt stops a fresh delivery right after the named writer
// commits, leaving one claim at that writer's revision and no later effect.
func operationalSeedAt(t *testing.T, fault reliablesubmit.OperationalOperation) (*operationalFixture, operationalHandoffResult, operationalPrestageState) {
	t.Helper()
	f := makeOperationalFixture(t, "")
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(fault, false); err != nil {
		t.Fatal(err)
	}
	first := f.submit()
	state := operationalPrestageStateAt(t, f)
	want := map[reliablesubmit.OperationalOperation]int{reliablesubmit.OperationalEstablish: 1, reliablesubmit.OperationalAssign: 2,
		reliablesubmit.OperationalIntent: 3, reliablesubmit.OperationalStamp: 4}[fault]
	if want == 0 || first.operation != fault || first.write != reliablesubmit.OperationalOwnCommitConfirmed ||
		state.Claims != 1 || state.Revision != want || state.Marker || state.Posts != 0 || f.egs.count() != 1 {
		t.Fatalf("seed after writer %d: %s state=%+v trust requests=%d", fault, operationalResultText(first), state, f.egs.count())
	}
	f.required.Store(0)
	f.evaluated.Store(0)
	return f, first, state
}

func operationalFixtureEvidence(t *testing.T, f *operationalFixture) evidencev1.ArtifactEvidence {
	t.Helper()
	var record evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

// operationalContentChange is one way a restarted Service's admission content
// can differ from the content the domain was commissioned with.
type operationalContentChange struct {
	name      string
	denies    bool
	configure func(*testing.T, *operationalFixture, *Service)
}

func operationalContentChanges() []operationalContentChange {
	return []operationalContentChange{
		{"configured literal denial", true, func(_ *testing.T, _ *operationalFixture, s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
		}},
		{"artifact revoked", true, func(t *testing.T, f *operationalFixture, s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				operationalFixtureEvidence(t, f).Claims.Package.Identity.ArtifactDigest)
		}},
		{"signer revoked", true, func(t *testing.T, f *operationalFixture, s *Service) {
			s.trustModel.SignerPolicy.RevokedSigners = append(s.trustModel.SignerPolicy.RevokedSigners,
				operationalFixtureEvidence(t, f).Seal.KeyID)
		}},
		{"signer no longer allowed", true, func(_ *testing.T, _ *operationalFixture, s *Service) {
			s.trustModel.SignerPolicy.AllowedSigners = []string{"another-signer"}
		}},
		{"changed verifier", true, func(t *testing.T, _ *operationalFixture, s *Service) {
			public, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			s.provenanceVerifier.publicKey = public
		}},
		{"unrelated revocation", false, func(_ *testing.T, _ *operationalFixture, s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				"sha256:"+strings.Repeat("e", 64))
		}},
	}
}

// operationalAllowingChange is content that allows the fixture's claim and
// differs from every entry of operationalContentChanges and from the
// fixture's own content, so it can always advance the domain.
func operationalAllowingChange(s *Service) {
	s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
		"sha256:"+strings.Repeat("c", 64))
}

// lateClock arms the proof seam of the fixture Service's view: once the
// returned flag is set, every later sample sees the confirmation deadline
// passed. It can only add elapsed time.
func (f *operationalFixture) lateClock() *atomic.Bool {
	late := new(atomic.Bool)
	operationalHooks(f.service).skew = func() time.Duration {
		if late.Load() {
			return admissionstate.ConfirmationLimit
		}
		return 0
	}
	return late
}

func operationalSealedObjects(t *testing.T, f *operationalFixture) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return len(entries)
}

// operationalRawWithKey is the fixture's request under another submit key, so
// that it is a different fresh delivery on the same domain.
func operationalRawWithKey(t *testing.T, f *operationalFixture, fill byte) []byte {
	t.Helper()
	var request map[string]json.RawMessage
	if err := json.Unmarshal(f.raw, &request); err != nil {
		t.Fatal(err)
	}
	key, err := json.Marshal(map[string]any{"contract": reliableSubmitContractV1,
		"submit_key": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	request["reliable_submit"] = key
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertOperationalCompleted(t *testing.T, f *operationalFixture, out operationalHandoffResult, what string) {
	t.Helper()
	if state := operationalPrestageStateAt(t, f); out.kind != operationalAccepted || out.run == "" || !out.receipt.Valid() ||
		state.Revision != 6 || !state.Marker || !state.Receipt || state.Posts != 1 {
		t.Fatalf("%s did not complete with exactly one POST: %s state=%+v", what, operationalResultText(out), state)
	}
}

// ---- Two Services on one domain (design section 10; audit AF-8 and R1 (a)) ----

func TestOperationalAdmissionGenerationsOnOneDomain(t *testing.T) {
	ctx := context.Background()
	for _, seed := range []struct {
		name  string
		fault reliablesubmit.OperationalOperation
	}{
		{"established", reliablesubmit.OperationalEstablish},
		{"run assigned", reliablesubmit.OperationalAssign},
		{"intent bound", reliablesubmit.OperationalIntent},
	} {
		for _, change := range operationalContentChanges() {
			t.Run(seed.name+"/"+change.name, func(t *testing.T) {
				f, _, seeded := operationalSeedAt(t, seed.fault)
				b, bEGS := operationalProofServiceWithEGS(t, f, func(s *Service) { change.configure(t, f, s) })
				if row := operationalAdmissionRowAt(t, f); row.Generation != 2 || row.State != 1 {
					t.Fatalf("changed content did not advance the domain: %+v", row)
				}
				// Service A still holds generation 1. It is fenced: it judges
				// nothing under its replaced content and it writes nothing.
				fenced := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				assertOperationalRefusal(t, f, seeded, fenced, reliablesubmit.OperationalUnavailable)
				if after := operationalPrestageStateAt(t, f); after != seeded || f.required.Load() != 0 || f.evaluated.Load() != 0 {
					t.Fatalf("fenced Service judged or wrote: before=%+v after=%+v required=%d evaluated=%d", seeded, after,
						f.required.Load(), f.evaluated.Load())
				}
				// Service B judges the in-flight claim under the content it
				// advanced to, after exactly one confirmation.
				second := b.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				if bEGS.count() != 1 {
					t.Fatalf("advancing Service made %d trust requests, want one", bEGS.count())
				}
				if change.denies {
					assertOperationalRefusal(t, f, seeded, second, reliablesubmit.OperationalDenied)
					if after := operationalPrestageStateAt(t, f); after != seeded {
						t.Fatalf("denied retry changed the claim: before=%+v after=%+v", seeded, after)
					}
				} else {
					assertOperationalCompleted(t, f, second, "retry under changed content that still allows the claim")
				}
				// Service C advances again with allowing content. A denial is
				// not terminal, and no path gives a second POST.
				c := operationalProofService(t, f, operationalAllowingChange)
				if row := operationalAdmissionRowAt(t, f); row.Generation != 3 || row.State != 1 {
					t.Fatalf("allowing content did not advance the domain: %+v", row)
				}
				third := c.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				assertOperationalCompleted(t, f, third, "retry under a later allowing generation")
				if !change.denies && (third.run != second.run || !third.receipt.Equal(second.receipt)) {
					t.Fatal("a later generation did not return the receipt the earlier one recorded")
				}
			})
		}
	}
}

// The run-assignment cut (revision 1 to 2) is refused without a usable view,
// and the establish gate stores nothing without one. Audit R1 (a) and (b);
// red-team RT-10.
func TestOperationalAdmissionRunAssignmentCutAndEstablishGate(t *testing.T) {
	ctx := context.Background()
	t.Run("run assignment/no view", func(t *testing.T) {
		f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
		for name, service := range map[string]*Service{
			"empty Service": {},
			"restarted Service that was never commissioned": func() *Service {
				s, _ := operationalUncommissionedService(t, f, nil)
				return s
			}(),
		} {
			out := service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
			if after := operationalPrestageStateAt(t, f); after != seeded {
				t.Fatalf("%s assigned a run or changed the claim: before=%+v after=%+v", name, seeded, after)
			}
		}
		assertOperationalCompleted(t, f, f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "allowed retry after refusals")
	})
	t.Run("run assignment/withdrawn domain", func(t *testing.T) {
		f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
		joined := operationalProofService(t, f, nil)
		if !f.service.withdrawOperationalEffects(ctx, f.domain) {
			t.Fatal("withdrawal was not confirmed")
		}
		for name, service := range map[string]*Service{"the Service that withdrew": f.service, "another Service on the domain": joined} {
			out := service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
			if after := operationalPrestageStateAt(t, f); after != seeded {
				t.Fatalf("%s assigned a run on a withdrawn domain: before=%+v after=%+v", name, seeded, after)
			}
		}
		next := operationalProofService(t, f, operationalAllowingChange)
		assertOperationalCompleted(t, f, next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "retry after the domain was enabled at a new generation")
	})
	// A fresh delivery that is refused stores no claim, charges no reservation,
	// seals no object and sends nothing.
	nothing := func(t *testing.T, f *operationalFixture, out operationalHandoffResult, what string) {
		t.Helper()
		if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			out.run != "" || out.receipt.Valid() || state.Claims != 0 || state.Grants != 0 || state.StageEntries != 0 || state.Posts != 0 ||
			operationalSealedObjects(t, f) != 0 {
			t.Fatalf("%s: %s state=%+v sealed=%d", what, operationalResultText(out), state, operationalSealedObjects(t, f))
		}
	}
	countEvidenceReads := func(f *operationalFixture) *atomic.Int32 {
		var reads atomic.Int32
		client := f.service.arsClient.client
		base := client.Transport
		client.Transport = admissionCountTransport(func(r *http.Request) (*http.Response, error) {
			reads.Add(1)
			return base.RoundTrip(r)
		})
		return &reads
	}
	t.Run("establish gate/never commissioned", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		reads := countEvidenceReads(f)
		s, _ := operationalUncommissionedService(t, f, nil)
		nothing(t, f, s.handoffOperational(ctx, f.domain, f.domain.caller, f.raw), "uncommissioned Service took a fresh delivery")
		// The first sample refuses before the ordinary resolver is asked.
		if reads.Load() != 0 {
			t.Fatalf("a Service without a view resolved the request (%d dependency reads)", reads.Load())
		}
		if out := f.submit(); out.kind != operationalAccepted || reads.Load() == 0 {
			t.Fatalf("control: the commissioned Service did not complete the same delivery: %s reads=%d", operationalResultText(out), reads.Load())
		}
	})
	t.Run("establish gate/withdrawn before the first sample", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		reads := countEvidenceReads(f)
		if !f.service.withdrawOperationalEffects(ctx, f.domain) {
			t.Fatal("withdrawal was not confirmed")
		}
		nothing(t, f, f.submit(), "withdrawn Service took a fresh delivery")
		if reads.Load() != 0 {
			t.Fatalf("a withdrawn Service resolved the request (%d dependency reads)", reads.Load())
		}
	})
	t.Run("establish gate/withdrawn between the two samples", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		reached := false
		f.domain.proof = &operationalHandoffProofHooks{beforeEstablish: func() {
			reached = f.service.withdrawOperationalEffects(ctx, f.domain)
		}}
		nothing(t, f, f.submit(), "withdrawal between the samples still established")
		if !reached {
			t.Fatal("the hook between the two samples did not run")
		}
	})
	t.Run("establish gate/deadline passes between the two samples", func(t *testing.T) {
		// The row stays enabled at the held token, so only the second sample
		// stands between an expired view and a stored claim.
		f := makeOperationalFixture(t, "")
		late := f.lateClock()
		f.domain.proof = &operationalHandoffProofHooks{beforeEstablish: func() { late.Store(true) }}
		nothing(t, f, f.submit(), "an expired view established a claim")
		if row := operationalAdmissionRowAt(t, f); !late.Load() || row.State != 1 || row.Generation != 1 {
			t.Fatalf("control: the domain is not still enabled at generation 1: %+v", row)
		}
		late.Store(false)
		f.domain.proof = nil
		assertOperationalCompleted(t, f, f.submit(), "the same delivery once the view is usable again")
	})
	t.Run("establish gate/fenced Service charges nothing", func(t *testing.T) {
		// Design 4.3: the fenced process holds a view it believes current. The
		// store refuses its token before a nonrefundable reservation is charged.
		f := makeOperationalFixture(t, "")
		next := operationalProofService(t, f, operationalAllowingChange)
		f.confirm()
		nothing(t, f, f.submit(), "fenced Service took a fresh delivery")
		assertOperationalCompleted(t, f, next.handoffOperational(ctx, f.domain, f.domain.caller, f.raw), "the current generation taking the same delivery")
		if state := operationalPrestageStateAt(t, f); state.Grants != 1 || operationalSealedObjects(t, f) != 1 {
			t.Fatalf("control: an admitted delivery did not charge exactly one reservation: %+v", state)
		}
	})
}

// A denial that arrives inside a writer turn refuses that write. A denial that
// arrives at the release qualifier, after COMMIT, keeps the write and
// withholds its result. Audit R1 (c) and (d).
func TestOperationalAdmissionDenialInsideEachWriter(t *testing.T) {
	ctx := context.Background()
	type shape struct {
		revision                     int
		intent, stage, stamp, marker bool
	}
	for _, w := range []struct {
		name string
		seed reliablesubmit.OperationalOperation
		// arm names the proof hook after which evaluations are counted. Empty
		// counts from the start, where evaluation 1 is the pre-check.
		arm             string
		op              reliablesubmit.OperationalOperation
		inTurn, release int
		refused, kept   shape
	}{
		{"run assignment", reliablesubmit.OperationalEstablish, "", reliablesubmit.OperationalAssign, 2, 3,
			shape{revision: 1}, shape{revision: 2}},
		{"intent", reliablesubmit.OperationalAssign, "", reliablesubmit.OperationalIntent, 2, 3,
			shape{revision: 2}, shape{revision: 3, intent: true}},
		{"stamp", reliablesubmit.OperationalIntent, "stamp", reliablesubmit.OperationalStamp, 1, 2,
			shape{revision: 3, intent: true, stage: true}, shape{revision: 4, intent: true, stage: true, stamp: true}},
		{"marker", reliablesubmit.OperationalIntent, "marker", reliablesubmit.OperationalMark, 1, 2,
			shape{revision: 4, intent: true, stage: true, stamp: true}, shape{revision: 5, intent: true, stage: true, stamp: true, marker: true}},
	} {
		for _, cut := range []struct {
			name      string
			release   bool
			withdrawn bool
		}{
			{"deadline passes inside the writer turn", false, false},
			{"deadline passes at the release qualifier", true, false},
			{"withdrawal at the release qualifier", true, true},
		} {
			t.Run(w.name+"/"+cut.name, func(t *testing.T) {
				f, _, _ := operationalSeedAt(t, w.seed)
				d := f.reopen()
				late := f.lateClock()
				armed, calls := w.arm == "", 0
				d.proof = &operationalHandoffProofHooks{}
				switch w.arm {
				case "stamp":
					d.proof.beforeStamp = func() { armed = true }
				case "marker":
					d.proof.beforeMarker = func() { armed = true }
				}
				at := w.inTurn
				if cut.release {
					at = w.release
				}
				operationalHooks(f.service).evaluated = func(allowed bool) {
					if !armed || !allowed {
						return
					}
					if calls++; calls != at {
						return
					}
					if !cut.withdrawn {
						late.Store(true)
					} else if !f.service.withdrawOperationalEffects(ctx, f.domain) {
						// The release qualifier runs after COMMIT, outside the turn.
						t.Error("withdrawal at the release qualifier was not confirmed")
					}
				}
				out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
				state := operationalPrestageStateAt(t, f)
				want, write := w.refused, reliablesubmit.OperationalRefused
				if cut.release {
					want, write = w.kept, reliablesubmit.OperationalAppliedReleaseFailed
				}
				got := shape{state.Revision, state.Intent, state.StageEntries != 0, state.Stamp, state.Marker}
				if calls != at || got != want || state.Posts != 0 || out.kind != operationalUnavailable ||
					out.reason != reliablesubmit.OperationalUnavailable || out.run != "" || out.receipt.Valid() ||
					out.operation != w.op || out.write != write {
					t.Fatalf("writer %d denied at evaluation %d: %s calls=%d state=%+v want=%+v", w.op, at, operationalResultText(out), calls, state, want)
				}
				// No later effect: the same Service stays stopped.
				again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				if after := operationalPrestageStateAt(t, f); after.Revision != state.Revision || after.Marker != state.Marker ||
					after.Stamp != state.Stamp || after.Posts != 0 || again.receipt.Valid() || again.kind == operationalAccepted {
					t.Fatalf("a stopped Service acted on a later call: %s before=%+v after=%+v", operationalResultText(again), state, after)
				}
			})
		}
	}
	t.Run("pre-stage/deadline passes inside the turn", func(t *testing.T) {
		f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalIntent)
		d := f.reopen()
		late := f.lateClock()
		armed, calls := false, 0
		d.proof = &operationalHandoffProofHooks{beforePrestage: func() { armed = true }}
		operationalHooks(f.service).evaluated = func(bool) {
			if armed {
				if calls++; calls == 1 {
					late.Store(true)
				}
			}
		}
		out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
		assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
		if after := operationalPrestageStateAt(t, f); calls != 1 || after != seeded {
			t.Fatalf("pre-stage denial created a stage or changed the claim: calls=%d before=%+v after=%+v", calls, seeded, after)
		}
	})
}

// A change of the domain's admission that lands between two writer turns is
// seen by the next first-effect cut. One sender that is already past its
// release re-read may still POST (design 5.4; red-team RT-4).
func TestOperationalAdmissionChangeAtEachProofHook(t *testing.T) {
	ctx := context.Background()
	type row struct {
		name, hook            string
		wantRevision          int
		wantStage, wantMarker bool
	}
	table := []row{
		{"before prestage", "prestage", 3, false, false},
		{"after stage create", "stamp", 3, true, false},
		{"before marker", "marker", 4, true, false},
		{"after marker before sender", "consume", 5, true, true},
		{"final protected sample", "entry", 5, true, true},
	}
	install := func(d *operationalDomain, hook string, act func()) {
		d.proof = &operationalHandoffProofHooks{}
		switch hook {
		case "prestage":
			d.proof.beforePrestage = act
		case "stamp":
			d.proof.beforeStamp = act
		case "marker":
			d.proof.beforeMarker = act
		case "consume":
			d.proof.beforeConsume = func(*liveSender, *handoffOwner) { act() }
		case "entry":
			d.proof.beforeEntrySample = act
		}
	}
	for _, change := range []struct {
		name string
		// local is true when the acting Service's own view stops, so even the
		// final sample refuses. Otherwise only the durable row changes.
		local bool
		act   func(*testing.T, *operationalFixture, *atomic.Bool) func()
	}{
		{"another Service advances", false, func(t *testing.T, f *operationalFixture, _ *atomic.Bool) func() {
			return func() { operationalProofService(t, f, operationalAllowingChange) }
		}},
		{"another Service withdraws the domain", false, func(t *testing.T, f *operationalFixture, _ *atomic.Bool) func() {
			joined := operationalProofService(t, f, nil)
			return func() {
				if !joined.withdrawOperationalEffects(ctx, f.domain) {
					t.Error("withdrawal by the second Service was not confirmed")
				}
			}
		}},
		{"the confirmation deadline passes", true, func(_ *testing.T, _ *operationalFixture, late *atomic.Bool) func() {
			return func() { late.Store(true) }
		}},
	} {
		for _, tc := range table {
			t.Run(change.name+"/"+tc.name, func(t *testing.T) {
				f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalIntent)
				d := f.reopen()
				late := f.lateClock()
				act := change.act(t, f, late)
				reached := false
				install(d, tc.hook, func() { reached = true; act() })
				out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
				state := operationalPrestageStateAt(t, f)
				if !reached {
					t.Fatal("the proof hook did not run")
				}
				if !change.local && (tc.hook == "consume" || tc.hook == "entry") {
					// The marker is committed and its release re-read has
					// passed: this one sender proceeds.
					assertOperationalCompleted(t, f, out, "sender already past its release re-read")
					// No later first-effect write commits on the domain for
					// the Service that was fenced or stopped.
					other := operationalRawWithKey(t, f, 0x32)
					later := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, other)
					if after := operationalPrestageStateAt(t, f); later.kind != operationalUnavailable ||
						later.reason != reliablesubmit.OperationalUnavailable || after.Claims != 1 || after.Posts != 1 || after.Grants != state.Grants {
						t.Fatalf("a later first effect committed after the change: %s state=%+v", operationalResultText(later), after)
					}
					return
				}
				if out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable || out.run != "" ||
					out.receipt.Valid() || state.Revision != tc.wantRevision || (state.StageEntries != 0) != tc.wantStage ||
					state.Marker != tc.wantMarker || state.Posts != 0 {
					t.Fatalf("change at %s was not seen by the next cut: %s state=%+v", tc.hook, operationalResultText(out), state)
				}
			})
		}
	}
}

// ---- Freshness (design 5.5 and section 10) ----

func TestOperationalAdmissionFreshness(t *testing.T) {
	ctx := context.Background()
	changed := func(f *operationalFixture) egscontract.RuntimeTrustPolicy {
		trust := snapshotRuntimeTrustModel(operationalInstalledView(f.service).Trust())
		trust.ArtifactPolicy.RevokedArtifacts = append(trust.ArtifactPolicy.RevokedArtifacts, "sha256:"+strings.Repeat("d", 64))
		return trust
	}
	t.Run("one trust request per effect-capable invocation and none otherwise", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		// A fresh delivery passes all three confirmation points.
		first := f.submit()
		assertOperationalCompleted(t, f, first, "fresh delivery")
		if f.egs.count() != 1 {
			t.Fatalf("fresh delivery made %d trust requests, want one", f.egs.count())
		}
		replay := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		recovered := f.service.recoverOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		if replay.kind != operationalAccepted || recovered.kind != operationalAccepted || replay.run != first.run ||
			recovered.run != first.run || f.egs.count() != 1 {
			t.Fatalf("accepted replay or recovery asked EGS: replay=%s recovered=%s requests=%d", operationalResultText(replay),
				operationalResultText(recovered), f.egs.count())
		}
		for _, fault := range []reliablesubmit.OperationalOperation{reliablesubmit.OperationalEstablish,
			reliablesubmit.OperationalAssign, reliablesubmit.OperationalIntent} {
			retained, _, _ := operationalSeedAt(t, fault)
			recovery := retained.service.recoverOperational(ctx, retained.reopen(), retained.domain.caller, retained.raw)
			if recovery.kind == operationalAccepted || retained.egs.count() != 1 {
				t.Fatalf("recovery of an unfinished claim asked EGS or completed it: %s requests=%d", operationalResultText(recovery), retained.egs.count())
			}
			assertOperationalCompleted(t, retained, retained.service.handoffOperational(ctx, retained.reopen(), retained.domain.caller, retained.raw),
				"retained continuation")
			if retained.egs.count() != 2 {
				t.Fatalf("continuation after writer %d made %d trust requests, want one", fault, retained.egs.count()-1)
			}
		}
		marked := makeOperationalFixture(t, "")
		if err := marked.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalAccept, true); err != nil {
			t.Fatal(err)
		}
		if seed := marked.submit(); seed.kind != operationalAmbiguous || marked.egs.count() != 1 {
			t.Fatalf("marked seed: %s requests=%d", operationalResultText(seed), marked.egs.count())
		}
		reconciled := marked.service.handoffOperational(ctx, marked.reopen(), marked.domain.caller, marked.raw)
		if reconciled.kind != operationalAccepted || marked.egs.count() != 1 || operationalPrestageStateAt(t, marked).Posts != 1 {
			t.Fatalf("marked reconciliation asked EGS or sent again: %s requests=%d", operationalResultText(reconciled), marked.egs.count())
		}
	})
	t.Run("different trust at EGS latches supersession", func(t *testing.T) {
		for _, seed := range []string{"fresh delivery", "retained claim"} {
			t.Run(seed, func(t *testing.T) {
				var f *operationalFixture
				if seed == "fresh delivery" {
					f = makeOperationalFixture(t, "")
				} else {
					f, _, _ = operationalSeedAt(t, reliablesubmit.OperationalEstablish)
				}
				before := operationalPrestageStateAt(t, f)
				requests := f.egs.count()
				original := snapshotRuntimeTrustModel(operationalInstalledView(f.service).Trust())
				f.egs.serve(changed(f))
				out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				assertOperationalRefusal(t, f, before, out, reliablesubmit.OperationalUnavailable)
				if after := operationalPrestageStateAt(t, f); after != before || f.evaluated.Load() != 0 || f.egs.count() != requests+1 {
					t.Fatalf("superseded Service reached a cut: before=%+v after=%+v evaluated=%d", before, after, f.evaluated.Load())
				}
				// The latch outlives the cause: EGS reverts, the process stays
				// stopped and does not ask again. Only a restart adopts trust.
				f.egs.serve(original)
				for i := 0; i < 2; i++ {
					again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
					assertOperationalRefusal(t, f, before, again, reliablesubmit.OperationalUnavailable)
				}
				if after := operationalPrestageStateAt(t, f); after != before || f.egs.count() != requests+1 {
					t.Fatalf("a superseded Service resumed after EGS reverted: after=%+v requests=%d", after, f.egs.count()-requests)
				}
				// The domain itself is untouched: a restarted Service with the
				// reverted content joins and completes.
				restarted := operationalProofService(t, f, nil)
				if row := operationalAdmissionRowAt(t, f); row.Generation != 1 || row.State != 1 {
					t.Fatalf("supersession changed the durable row: %+v", row)
				}
				assertOperationalCompleted(t, f, restarted.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "restarted Service")
			})
		}
	})
	t.Run("a failed confirmation extends nothing", func(t *testing.T) {
		for _, failure := range []string{"unreachable", "bad signature", "unverifiable key"} {
			t.Run(failure, func(t *testing.T) {
				f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
				held := f.service.operational.Inspect(f.service).Confirmed
				if held.IsZero() {
					t.Fatal("control: the seeding invocation recorded no confirmation")
				}
				switch failure {
				case "unreachable":
					f.egs.failing(true)
				case "bad signature":
					f.egs.forging(true)
				case "unverifiable key":
					f.service.trustModelVerifier.keyID = "another-egs-key"
				}
				f.service.confirmOperationalAdmission(ctx)
				if f.service.operational.Inspect(f.service).Confirmed != held || f.service.operational.Inspect(f.service).Superseded || f.egs.count() != 2 {
					t.Fatalf("a failed confirmation changed the Service: confirmed moved=%t superseded=%t requests=%d",
						f.service.operational.Inspect(f.service).Confirmed != held, f.service.operational.Inspect(f.service).Superseded, f.egs.count())
				}
				// Once the deadline of the last good confirmation has passed,
				// every cut refuses, however often EGS is asked.
				late := f.lateClock()
				late.Store(true)
				out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
				if after := operationalPrestageStateAt(t, f); after != seeded || f.evaluated.Load() != 0 || f.egs.count() != 3 {
					t.Fatalf("an unconfirmed Service reached a cut: after=%+v evaluated=%d requests=%d", after, f.evaluated.Load(), f.egs.count())
				}
				// Inside the deadline the earlier confirmation still serves.
				late.Store(false)
				assertOperationalCompleted(t, f, f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw),
					"continuation inside the deadline of the last good confirmation")
			})
		}
		t.Run("control: a good confirmation moves the deadline forward", func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			f.confirm()
			first := f.service.operational.Inspect(f.service).Confirmed
			time.Sleep(2 * time.Millisecond)
			f.confirm()
			if second := f.service.operational.Inspect(f.service).Confirmed; !second.After(first) || second.After(time.Now()) {
				t.Fatalf("confirmation time did not advance: first=%s second=%s", first, second)
			}
		})
		t.Run("the recorded time is sampled before the request is sent", func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			var during time.Time
			f.egs.observe(func() {
				time.Sleep(2 * time.Millisecond)
				during = time.Now()
			})
			f.confirm()
			if during.IsZero() || !f.service.operational.Inspect(f.service).Confirmed.Before(during) {
				t.Fatalf("confirmation time %s is not earlier than the request %s", f.service.operational.Inspect(f.service).Confirmed, during)
			}
		})
	})
	// Two confirmations can overlap: each invocation asks once, and invocations
	// run concurrently. The one that started first vouches for an earlier
	// moment, so when it finishes last it must not replace the later time.
	t.Run("a confirmation that started earlier and finishes later does not move the time back", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		confirmedAt := func() time.Time {
			f.service.mu.RLock()
			defer f.service.mu.RUnlock()
			return f.service.operational.Inspect(f.service).Confirmed
		}
		var requests atomic.Int32
		entered, release := make(chan struct{}), make(chan struct{})
		f.egs.observe(func() {
			// Only the first request is held at EGS.
			if requests.Add(1) == 1 {
				close(entered)
				<-release
			}
		})
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			f.service.confirmOperationalAdmission(ctx)
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first confirmation did not reach EGS")
		}
		if held := confirmedAt(); !held.IsZero() {
			t.Fatalf("control: a confirmation was recorded while the only request was still held: %s", held)
		}
		time.Sleep(2 * time.Millisecond)
		f.service.confirmOperationalAdmission(ctx)
		later := confirmedAt()
		if later.IsZero() {
			t.Fatal("control: the second confirmation recorded nothing")
		}
		close(release)
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("the held confirmation did not finish")
		}
		if final := confirmedAt(); final != later || requests.Load() != 2 || f.service.operational.Inspect(f.service).Superseded {
			t.Fatalf("the earlier confirmation changed the recorded time: later=%s final=%s requests=%d", later, final, requests.Load())
		}
	})
	t.Run("a Service that was never confirmed admits nothing", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		f.egs.failing(true)
		if _, ok := f.service.currentOperationalAdmission(f.domain.realm); ok {
			t.Fatal("a view without a confirmation is current")
		}
		out := f.submit()
		if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			state.Claims != 0 || state.Grants != 0 || f.egs.count() != 1 {
			t.Fatalf("an unconfirmed Service took a fresh delivery: %s state=%+v", operationalResultText(out), state)
		}
		f.egs.failing(false)
		assertOperationalCompleted(t, f, f.submit(), "the same delivery after a first good confirmation")
	})
	t.Run("the confirmation never overlaps a writer turn", func(t *testing.T) {
		probe := func(f *operationalFixture) error {
			conn, err := f.db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				return err
			}
			_, err = conn.ExecContext(ctx, "ROLLBACK")
			return err
		}
		for _, seed := range []reliablesubmit.OperationalOperation{0, reliablesubmit.OperationalEstablish,
			reliablesubmit.OperationalAssign, reliablesubmit.OperationalIntent} {
			var f *operationalFixture
			if seed == 0 {
				f = makeOperationalFixture(t, "")
			} else {
				f, _, _ = operationalSeedAt(t, seed)
			}
			probes, busy := 0, 0
			f.egs.observe(func() {
				probes++
				if err := probe(f); err != nil {
					busy++
					t.Errorf("writer lock was held while EGS was asked (seed %d): %v", seed, err)
				}
			})
			assertOperationalCompleted(t, f, f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "probed invocation")
			if probes != 1 || busy != 0 {
				t.Fatalf("seed %d: probes=%d busy=%d", seed, probes, busy)
			}
		}
		// Control: the same probe fails when it runs inside a writer turn.
		f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
		calls := 0
		var inside error
		operationalHooks(f.service).evaluated = func(bool) {
			if calls++; calls == 2 {
				inside = probe(f)
			}
		}
		assertOperationalCompleted(t, f, f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "control invocation")
		if inside == nil {
			t.Fatal("control: BEGIN IMMEDIATE succeeded inside the run-assignment writer turn")
		}
	})
}

// Every sample of the view is a point where the deadline can pass. The sweep
// moves that point over every freshness read of one complete fresh delivery.
// Whichever sample sees it first, that sample is the last thing the
// invocation does to the claim: nothing is written, staged or sent after it,
// and no run or receipt is disclosed. This pins the last sample before each
// effect, wherever it sits.
func TestOperationalAdmissionDeadlineAtEverySample(t *testing.T) {
	type observation struct {
		f     *operationalFixture
		mu    sync.Mutex
		reads int
		seen  bool
		at    operationalPrestageState
		out   operationalHandoffResult
	}
	run := func(t *testing.T, at int) *observation {
		t.Helper()
		o := &observation{f: makeOperationalFixture(t, "")}
		operationalHooks(o.f.service).skew = func() time.Duration {
			o.mu.Lock()
			defer o.mu.Unlock()
			if o.reads++; o.reads == at {
				o.seen, o.at = true, operationalPrestageStateAt(t, o.f)
			}
			if o.seen {
				return admissionstate.ConfirmationLimit
			}
			return 0
		}
		o.out = o.f.submit()
		return o
	}
	control := run(t, 0)
	assertOperationalCompleted(t, control.f, control.out, "control: a delivery whose deadline never passes")
	// The number is exact so that adding or dropping a sample is a deliberate
	// change: a dropped sample would otherwise only shorten the sweep.
	if control.seen || control.reads != 48 {
		t.Fatalf("control: a complete fresh delivery sampled the view %d times, want 48 (deadline seen=%t)", control.reads, control.seen)
	}
	// reached records the state of the claim at the sample that saw the
	// deadline, so the sweep is known to have stood before every writer.
	type stage struct {
		revision int
		staged   bool
	}
	reached := map[stage]int{}
	for at := 1; at <= control.reads; at++ {
		t.Run(fmt.Sprintf("sample %d of %d", at, control.reads), func(t *testing.T) {
			o := run(t, at)
			after := operationalPrestageStateAt(t, o.f)
			if !o.seen {
				t.Fatalf("the invocation ended after %d samples, before sample %d", o.reads, at)
			}
			if o.out.kind != operationalUnavailable || o.out.reason != reliablesubmit.OperationalUnavailable ||
				o.out.run != "" || o.out.receipt.Valid() || after.Posts != 0 || after.Receipt || after != o.at {
				t.Fatalf("an effect or a disclosure followed the sample that saw the deadline: %s at the sample=%+v after=%+v",
					operationalResultText(o.out), o.at, after)
			}
			reached[stage{o.at.Revision, o.at.StageEntries != 0}]++
		})
	}
	for _, want := range []stage{{0, false}, {1, false}, {2, false}, {3, false}, {3, true}, {4, true}, {5, true}} {
		if reached[want] == 0 {
			t.Errorf("no sample stood at revision %d (staged=%t); the sweep reached %v", want.revision, want.staged, reached)
		}
	}
}

// The qualifier samples the view again after it has evaluated. A passed
// deadline, a withdrawal or a supersession that arrives during the
// evaluation makes that judgment unusable, also for a caller that asks the
// qualifier directly and not through a writer cut.
func TestOperationalAdmissionChangeDuringEvaluation(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		arrive func(t *testing.T, f *operationalFixture, late *atomic.Bool)
	}{
		{"the deadline passes", func(_ *testing.T, _ *operationalFixture, late *atomic.Bool) { late.Store(true) }},
		{"the domain is withdrawn", func(t *testing.T, f *operationalFixture, _ *atomic.Bool) {
			if !f.service.withdrawOperationalEffects(ctx, f.domain) {
				t.Error("control: the withdrawal was not confirmed")
			}
		}},
		{"EGS serves other trust", func(t *testing.T, f *operationalFixture, _ *atomic.Bool) {
			trust := snapshotRuntimeTrustModel(operationalInstalledView(f.service).Trust())
			trust.ArtifactPolicy.RevokedArtifacts = append(trust.ArtifactPolicy.RevokedArtifacts, "sha256:"+strings.Repeat("d", 64))
			f.egs.serve(trust)
			requests := f.egs.count()
			f.service.confirmOperationalAdmission(ctx)
			if f.egs.count() != requests+1 {
				t.Error("control: the confirmation did not ask EGS")
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			original := operationalV2Original(t, f)
			f.confirm()
			late := f.lateClock()
			calls := 0
			operationalHooks(f.service).evaluated = func(allowed bool) {
				if calls++; calls != 2 {
					return
				}
				if !allowed {
					t.Error("control: the interrupted evaluation did not allow the claim")
				}
				c.arrive(t, f, late)
			}
			if reason := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalReasonNone || calls != 1 {
				t.Fatalf("control: an undisturbed evaluation: reason=%d evaluations=%d", reason, calls)
			}
			if reason := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalUnavailable || calls != 2 {
				t.Fatalf("a judgment made before the change was returned: reason=%d evaluations=%d", reason, calls)
			}
			// The change is not undone by asking again.
			if reason := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalUnavailable || calls != 2 {
				t.Fatalf("a stopped view judged again: reason=%d evaluations=%d", reason, calls)
			}
		})
	}
}

// ---- Outcomes (design 5.6; red-team RT-2) ----

// operationalFutureInputPolicy asks for an input class the retained path
// cannot supply. No production path can commission it; the test adds it
// through the proof seam, behind the built-in set of the view, to reach the
// unsupported-input branch.
type operationalFutureInputPolicy struct{}

func (operationalFutureInputPolicy) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return []AdmissionPolicyInputClass{"future_input"}
}

func (operationalFutureInputPolicy) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	return DenyAdmissionPolicyDecision("unreachable", "unreachable", "unreachable")
}

// Every cause maps to its value-free reason at a first-effect cut, and none
// discloses a run or a receipt or changes the claim.
func TestOperationalAdmissionOutcomeMapping(t *testing.T) {
	ctx := context.Background()
	denied, unavailable, integrity := reliablesubmit.OperationalDenied, reliablesubmit.OperationalUnavailable, reliablesubmit.OperationalIntegrity
	if denied == unavailable || denied == integrity || denied == reliablesubmit.OperationalReasonNone {
		t.Fatal("OperationalDenied is not a reason of its own")
	}
	type arranged struct {
		service *Service
		domain  *operationalDomain
	}
	through := func(change string) func(*testing.T, *operationalFixture) arranged {
		return func(t *testing.T, f *operationalFixture) arranged {
			for _, candidate := range operationalContentChanges() {
				if candidate.name == change {
					return arranged{operationalProofService(t, f, func(s *Service) { candidate.configure(t, f, s) }), f.reopen()}
				}
			}
			t.Fatalf("unknown content change %q", change)
			return arranged{}
		}
	}
	causes := []struct {
		name    string
		reason  reliablesubmit.OperationalReason
		arrange func(*testing.T, *operationalFixture) arranged
	}{
		// Denied: the current content refuses this claim.
		{"signer not allowed", denied, through("signer no longer allowed")},
		{"signer revoked", denied, through("signer revoked")},
		{"artifact revoked", denied, through("artifact revoked")},
		{"built-in policy denies", denied, through("configured literal denial")},
		{"retained evidence does not verify under the current verifier", denied, through("changed verifier")},
		{"verifier key id rotated", denied, func(t *testing.T, f *operationalFixture) arranged {
			return arranged{operationalProofService(t, f, func(s *Service) { s.provenanceVerifier.keyID = "rotated-provenance-key" }), f.reopen()}
		}},
		// Unavailable: this process cannot judge now.
		{"no view", unavailable, func(_ *testing.T, f *operationalFixture) arranged { return arranged{&Service{}, f.reopen()} }},
		{"token mismatch", unavailable, func(t *testing.T, f *operationalFixture) arranged {
			operationalProofService(t, f, operationalAllowingChange)
			return arranged{f.service, f.reopen()}
		}},
		{"withdrawn by this Service", unavailable, func(t *testing.T, f *operationalFixture) arranged {
			if !f.service.withdrawOperationalEffects(ctx, f.domain) {
				t.Fatal("withdrawal was not confirmed")
			}
			return arranged{f.service, f.reopen()}
		}},
		{"withdrawn by another Service", unavailable, func(t *testing.T, f *operationalFixture) arranged {
			if !operationalProofService(t, f, nil).withdrawOperationalEffects(ctx, f.domain) {
				t.Fatal("withdrawal was not confirmed")
			}
			return arranged{f.service, f.reopen()}
		}},
		{"superseded", unavailable, func(_ *testing.T, f *operationalFixture) arranged {
			trust := snapshotRuntimeTrustModel(operationalInstalledView(f.service).Trust())
			trust.SignerPolicy.RevokedSigners = append(trust.SignerPolicy.RevokedSigners, "an-unrelated-signer")
			f.egs.serve(trust)
			return arranged{f.service, f.reopen()}
		}},
		{"deadline passed", unavailable, func(_ *testing.T, f *operationalFixture) arranged {
			f.lateClock().Store(true)
			return arranged{f.service, f.reopen()}
		}},
		{"unsupported input", unavailable, func(_ *testing.T, f *operationalFixture) arranged {
			operationalHooks(f.service).stricter = operationalFutureInputPolicy{}
			return arranged{f.service, f.reopen()}
		}},
		// Integrity: the stored original does not fit the domain reading it.
		{"existing original read through another epoch", integrity, func(t *testing.T, f *operationalFixture) arranged {
			return arranged{f.service, redTeamRealmDomain(t, f, func(r *operationalRealm) { r.epoch++ })}
		}},
		{"existing original read through another installation", integrity, func(t *testing.T, f *operationalFixture) arranged {
			return arranged{f.service, redTeamRealmDomain(t, f, func(r *operationalRealm) { r.installation[7] ^= 0x40 })}
		}},
	}
	for _, seed := range []struct {
		name  string
		fault reliablesubmit.OperationalOperation
	}{{"at the run-assignment cut", reliablesubmit.OperationalEstablish}, {"at the pre-stage cut", reliablesubmit.OperationalIntent}} {
		for _, cause := range causes {
			t.Run(seed.name+"/"+cause.name, func(t *testing.T) {
				f, _, seeded := operationalSeedAt(t, seed.fault)
				with := cause.arrange(t, f)
				out := with.service.handoffOperational(ctx, with.domain, with.domain.caller, f.raw)
				assertOperationalRefusal(t, f, seeded, out, cause.reason)
				if after := operationalPrestageStateAt(t, f); after != seeded {
					t.Fatalf("refused cut changed the claim: before=%+v after=%+v", seeded, after)
				}
			})
		}
	}
	t.Run("contradictory authenticated evidence is Integrity", func(t *testing.T) {
		// The evidence vectors of TestOperationalRetainedAdmissionEvidenceV2 pin
		// each contradiction; this pins the order: association before signature.
		f := makeOperationalFixture(t, "")
		f.confirm()
		original := operationalV2Original(t, f)
		forged := original
		record := operationalFixtureEvidence(t, f)
		record.Claims.Admission.Authorization.Derivation.OutputID = "other"
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		forged.resolved.provenanceRecord = string(encoded)
		if reason := f.service.qualifyOperationalRetained(ctx, forged, f.domain.realm); reason != integrity {
			t.Fatalf("evidence that contradicts the original and no longer verifies: reason=%d, want Integrity", reason)
		}
		forged.resolved.provenanceRecord = "{"
		if reason := f.service.qualifyOperationalRetained(ctx, forged, f.domain.realm); reason != integrity {
			t.Fatalf("malformed evidence: reason=%d, want Integrity", reason)
		}
	})
}

// ---- Pins for the low audit items and red-team caveats (plan 4.7) ----

// AF-6. When a call is both cancelled and refused by the authority, the
// authority refusal is reported, because it withholds the run and Canceled
// alone does not.
func TestOperationalAdmissionRefusalPrecedesCancellation(t *testing.T) {
	t.Run("final sender entry", func(t *testing.T) {
		// Cancelled and withdrawn before the admission sample of the entry.
		f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalIntent)
		d := f.reopen()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reached := false
		d.proof = &operationalHandoffProofHooks{beforeEntrySample: func() {
			reached = f.service.withdrawOperationalEffects(context.Background(), f.domain)
			cancel()
		}}
		out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if !reached || ctx.Err() == nil || out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			out.run != "" || out.receipt.Valid() || !state.Marker || state.Posts != 0 {
			t.Fatalf("cancelled and refused entry: %s state=%+v", operationalResultText(out), state)
		}
	})
	t.Run("reconcile", func(t *testing.T) {
		// The entry is refused by the authority while the context is still
		// live; the cancellation arrives before the result is reconciled.
		f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalIntent)
		d := f.reopen()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		armed, fired := false, false
		operationalHooks(f.service).skew = func() time.Duration {
			if !armed {
				return 0
			}
			// This is the admission sample of the sender entry.
			fired = true
			cancel()
			return admissionstate.ConfirmationLimit
		}
		d.proof = &operationalHandoffProofHooks{beforeEntrySample: func() { armed = true }}
		out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if !fired || ctx.Err() == nil || out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
			out.run != "" || out.receipt.Valid() || !state.Marker || state.Posts != 0 {
			t.Fatalf("refused entry then cancellation: %s state=%+v", operationalResultText(out), state)
		}
	})
	t.Run("control: cancellation alone returns the stored run", func(t *testing.T) {
		f, first, _ := operationalSeedAt(t, reliablesubmit.OperationalIntent)
		d := f.reopen()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d.proof = &operationalHandoffProofHooks{beforeEntrySample: cancel}
		out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if out.reason != reliablesubmit.OperationalCanceled || out.run != first.run || out.kind != operationalAmbiguous ||
			!state.Marker || state.Posts != 0 {
			t.Fatalf("cancelled entry under an allowing authority: %s state=%+v", operationalResultText(out), state)
		}
	})
}

// AF-7. A denial never erases a committed write. The result has one write
// slot, which reports the last writer attempted in that call.
func TestOperationalAdmissionResultReportsLastAttemptedWriter(t *testing.T) {
	for _, tc := range []struct {
		hook         string
		operation    reliablesubmit.OperationalOperation
		write        reliablesubmit.OperationalDisposition
		wantRevision int
		wantStage    bool
	}{
		// Pre-stage writes nothing: the intent applied in this call is reported.
		{"prestage", reliablesubmit.OperationalIntent, reliablesubmit.OperationalApplied, 3, false},
		// The stamp writer is attempted and refused: it is reported, and the
		// intent committed earlier in the same call stays committed.
		{"stamp", reliablesubmit.OperationalStamp, reliablesubmit.OperationalRefused, 3, true},
		// The marker writer is not attempted without a view: the stamp applied
		// in this call is reported.
		{"marker", reliablesubmit.OperationalStamp, reliablesubmit.OperationalApplied, 4, true},
	} {
		t.Run(tc.hook, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			withdraw := func() {
				if !f.service.withdrawOperationalEffects(context.Background(), f.domain) {
					t.Error("withdrawal between turns was not confirmed")
				}
			}
			f.domain.proof = &operationalHandoffProofHooks{}
			switch tc.hook {
			case "prestage":
				f.domain.proof.beforePrestage = withdraw
			case "stamp":
				f.domain.proof.beforeStamp = withdraw
			case "marker":
				f.domain.proof.beforeMarker = withdraw
			}
			out := f.submit()
			state := operationalPrestageStateAt(t, f)
			if out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable || out.run != "" ||
				out.operation != tc.operation || out.write != tc.write || state.Revision != tc.wantRevision ||
				!state.Intent || (state.StageEntries != 0) != tc.wantStage || state.Marker || state.Posts != 0 {
				t.Fatalf("same-call write then denial at %s: %s state=%+v", tc.hook, operationalResultText(out), state)
			}
		})
	}
}

// AF-9 and RT-3. A refused first-effect cut returns a value-free result. An
// entry that attempts no cut (recovery, a stamped retry) returns the stored
// facts to the authenticated original caller under any authority, writes
// nothing and asks EGS nothing. Withholding at a refused cut is a result-shape
// rule, not a confidentiality boundary.
func TestOperationalAdmissionEntriesWithoutACutReturnStoredFacts(t *testing.T) {
	ctx := context.Background()
	type authority struct {
		name    string
		arrange func(*testing.T, *operationalFixture) (*Service, func() int)
	}
	requests := func(egs *operationalTrustAuthority) func() int { return egs.count }
	authorities := []authority{
		{"allowing", func(_ *testing.T, f *operationalFixture) (*Service, func() int) { return f.service, requests(f.egs) }},
		{"absent", func(*testing.T, *operationalFixture) (*Service, func() int) {
			return &Service{}, func() int { return 0 }
		}},
		{"denying", func(t *testing.T, f *operationalFixture) (*Service, func() int) {
			s, egs := operationalProofServiceWithEGS(t, f, func(s *Service) {
				configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
			})
			return s, requests(egs)
		}},
		{"fenced", func(t *testing.T, f *operationalFixture) (*Service, func() int) {
			operationalProofService(t, f, operationalAllowingChange)
			return f.service, requests(f.egs)
		}},
		{"withdrawn", func(t *testing.T, f *operationalFixture) (*Service, func() int) {
			if !f.service.withdrawOperationalEffects(ctx, f.domain) {
				t.Fatal("withdrawal was not confirmed")
			}
			return f.service, requests(f.egs)
		}},
	}
	for _, entry := range []struct {
		name     string
		fault    reliablesubmit.OperationalOperation
		recovery bool
		kind     operationalResultKind
	}{
		{"stamped retry", reliablesubmit.OperationalStamp, false, operationalPending},
		{"recovery of a stamped claim", reliablesubmit.OperationalStamp, true, operationalPending},
		{"recovery of a claim with a run and no stamp", reliablesubmit.OperationalIntent, true, operationalPending},
	} {
		for _, a := range authorities {
			t.Run(entry.name+"/"+a.name, func(t *testing.T) {
				f, first, seeded := operationalSeedAt(t, entry.fault)
				if first.run == "" {
					t.Fatal("seed assigned no run")
				}
				service, count := a.arrange(t, f)
				before := count()
				f.evaluated.Store(0)
				out := service.operatePrivateHandoff(ctx, f.reopen(), f.domain.caller, f.raw, entry.recovery)
				if after := operationalPrestageStateAt(t, f); out.kind != entry.kind || out.run != first.run || out.receipt.Valid() ||
					out.operation != 0 || out.write != 0 || after != seeded || count() != before || f.evaluated.Load() != 0 {
					t.Fatalf("entry without a cut: %s before=%+v after=%+v trust requests=%d evaluated=%d", operationalResultText(out), seeded, after,
						count()-before, f.evaluated.Load())
				}
			})
		}
	}
	// The other half of the rule: with the same claim one step earlier, the
	// handoff entry attempts a cut, and a refusal there is value-free.
	t.Run("control: a refused cut withholds the same run", func(t *testing.T) {
		f, first, seeded := operationalSeedAt(t, reliablesubmit.OperationalIntent)
		out := (&Service{}).handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		if first.run == "" {
			t.Fatal("seed assigned no run")
		}
		assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
	})
}

// O-5 and RT-5. A denial before staging does not poison the claim: a later
// allowing generation completes it (TestOperationalAdmissionGenerationsOnOneDomain).
// After staging, the claim keeps its stage residue: no later retry sends it,
// and the caller needs a new submit key.
func TestOperationalAdmissionDenialAfterStagingKeepsResidue(t *testing.T) {
	ctx := context.Background()
	f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalIntent)
	d := f.reopen()
	late := f.lateClock()
	d.proof = &operationalHandoffProofHooks{beforeStamp: func() { late.Store(true) }}
	refused := f.service.handoffOperational(ctx, d, d.caller, f.raw)
	staged := operationalPrestageStateAt(t, f)
	if refused.kind != operationalUnavailable || refused.reason != reliablesubmit.OperationalUnavailable || staged.Revision != 3 ||
		staged.StageEntries != 1 || staged.Stamp || staged.Posts != 0 {
		t.Fatalf("denial at the stamp cut: %s state=%+v", operationalResultText(refused), staged)
	}
	late.Store(false)
	// In this order: the later generation fences the fixture's own Service.
	for _, name := range []string{"same generation", "later allowing generation"} {
		service := f.service
		if name == "later allowing generation" {
			service = operationalProofService(t, f, operationalAllowingChange)
		}
		out := service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		if after := operationalPrestageStateAt(t, f); out.kind == operationalAccepted || out.receipt.Valid() ||
			out.reason != reliablesubmit.OperationalOccupiedReason || after.Revision != 3 || after.StageEntries != 1 || after.Stamp ||
			after.Marker || after.Posts != 0 {
			t.Fatalf("%s retried a claim with stage residue: %s state=%+v", name, operationalResultText(out), after)
		}
	}
	// A new submit key is a new claim and completes.
	fresh := operationalRawWithKey(t, f, 0x33)
	last := operationalProofService(t, f, func(s *Service) {
		s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts, "sha256:"+strings.Repeat("b", 64))
	})
	out := last.handoffOperational(ctx, f.reopen(), f.domain.caller, fresh)
	var claims, accepted int
	if err := f.db.QueryRow("SELECT count(*), coalesce(sum(receipt_ref IS NOT NULL),0) FROM reliable_submit_claims").Scan(&claims, &accepted); err != nil {
		t.Fatal(err)
	}
	if posts, _, _ := f.receiver.counts(); out.kind != operationalAccepted || claims != 2 || accepted != 1 || posts != 1 {
		t.Fatalf("new submit key after residue: %s claims=%d accepted=%d posts=%d", operationalResultText(out), claims, accepted, posts)
	}
}

// ---- The realm a view is bound to (red-team RT-10, the installation check) ----

// The admission row and the token name one installation and one epoch. A
// correctly commissioned and confirmed Service that is handed a domain
// qualified for another installation or epoch holds a token the store would
// accept, so only the comparison of the view with the domain's realm keeps it
// from establishing a claim sealed for a realm the row does not name.
func TestOperationalAdmissionViewIsBoundToTheDomainRealm(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(*operationalRealm){
		"another epoch":        func(r *operationalRealm) { r.epoch++ },
		"another installation": func(r *operationalRealm) { r.installation[5] ^= 0x10 },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			var reads atomic.Int32
			client := f.service.arsClient.client
			base := client.Transport
			client.Transport = admissionCountTransport(func(r *http.Request) (*http.Response, error) {
				reads.Add(1)
				return base.RoundTrip(r)
			})
			other := redTeamRealmDomain(t, f, change)
			f.confirm()
			row := operationalAdmissionRowAt(t, f)
			out := f.service.handoffOperational(ctx, other, other.caller, f.raw)
			if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalUnavailable ||
				out.run != "" || state.Claims != 0 || state.Grants != 0 || state.Posts != 0 || operationalSealedObjects(t, f) != 0 || reads.Load() != 0 {
				t.Fatalf("a view acted through a domain of %s: %s state=%+v dependency reads=%d", name, operationalResultText(out), state, reads.Load())
			}
			// It cannot stop a domain it is not bound to either, and the refusal
			// leaves it usable on its own.
			if f.service.withdrawOperationalEffects(ctx, other) || operationalAdmissionRowAt(t, f) != row {
				t.Fatalf("a view withdrew through a domain of %s", name)
			}
			if _, ok := f.service.currentOperationalAdmission(f.domain.realm); !ok {
				t.Fatal("a refused withdrawal stopped the Service on its own domain")
			}
			// No restarted Service can be commissioned through that domain.
			fresh, _ := operationalUncommissionedService(t, f, nil)
			if err := fresh.commissionOperationalAdmission(ctx, other); err == nil || operationalInstalledView(fresh).Installed() {
				t.Fatalf("the store commissioned a view for %s", name)
			}
			if err := fresh.advanceOperationalAdmission(ctx, other, row.Generation); err == nil || operationalInstalledView(fresh).Installed() ||
				operationalAdmissionRowAt(t, f) != row {
				t.Fatalf("the store advanced the domain for %s", name)
			}
			// Control: the same Service completes the same delivery on its own domain.
			assertOperationalCompleted(t, f, f.submit(), "the delivery on the domain the view is bound to")
			if reads.Load() == 0 {
				t.Fatal("control: the resolver's dependency reads were not counted")
			}
		})
	}
}

// ---- Two processes (design section 10) ----

// A second process is commissioned at the domain's generation, binds the
// intent of a retained claim and is held between two writer turns. This
// process then changes the domain's admission row. The held process holds a
// view it believes current; its next cut reads the row under the writer lock
// and refuses, so it stages nothing and sends nothing.
func TestOperationalAdmissionFencesAnotherProcess(t *testing.T) {
	for _, change := range []string{"advance", "withdrawal"} {
		t.Run(change, func(t *testing.T) {
			// The other process has no resolver: it continues a retained claim.
			f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalAssign)
			fixture := f.childFixture()
			fixture.HoldBeforePrestage = true
			raw, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "held-process.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := startOperationalChild(t, ctx, path)
			await := func(signal <-chan struct{}, what string) {
				t.Helper()
				select {
				case <-signal:
				case logs := <-child.result:
					t.Fatalf("the other process stopped before %s:\n%s", what, logs)
				case <-ctx.Done():
					t.Fatalf("timeout before %s", what)
				}
			}
			await(child.ready, "readiness")
			if _, err := fmt.Fprintln(child.input, "go"); err != nil {
				t.Fatal(err)
			}
			await(child.held, "its hold between the intent and the pre-stage turn")
			held := operationalPrestageStateAt(t, f)
			if row := operationalAdmissionRowAt(t, f); held.Claims != 1 || held.Revision != 3 || !held.Intent || held.StageEntries != 0 ||
				held.Posts != 0 || row.Generation != 1 || row.State != 1 {
				t.Fatalf("the other process is not held at a bound intent under generation 1: state=%+v row=%+v", held, row)
			}
			var next *Service
			if change == "advance" {
				next = operationalProofService(t, f, operationalAllowingChange)
			} else if !f.service.withdrawOperationalEffects(ctx, f.domain) {
				t.Fatal("withdrawal was not confirmed")
			}
			if _, err := fmt.Fprintln(child.input, "go"); err != nil {
				t.Fatal(err)
			}
			var logs string
			select {
			case logs = <-child.result:
			case <-ctx.Done():
				t.Fatal("the held process did not finish")
			}
			var kind, reason, operation, write int
			var run, receipt, found bool
			for _, line := range strings.Split(logs, "\n") {
				if rest, ok := strings.CutPrefix(line, "ES_OPERATIONAL_CHILD_HELD_RESULT "); ok {
					if _, err := fmt.Sscan(rest, &kind, &reason, &operation, &write, &run, &receipt); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found || !strings.Contains(logs, "--- PASS: TestOperationalHandoffChildProcess") {
				t.Fatalf("the held process did not report a result:\n%s", logs)
			}
			after := operationalPrestageStateAt(t, f)
			if operationalResultKind(kind) != operationalUnavailable || reliablesubmit.OperationalReason(reason) != reliablesubmit.OperationalUnavailable ||
				run || receipt || after != held {
				t.Fatalf("a process holding the replaced generation acted: kind=%d reason=%d operation=%d write=%d run=%t receipt=%t before=%+v after=%+v",
					kind, reason, operation, write, run, receipt, held, after)
			}
			// The intent the held process committed in the same call stays
			// reported; the pre-stage turn wrote nothing.
			if reliablesubmit.OperationalOperation(operation) != reliablesubmit.OperationalIntent ||
				reliablesubmit.OperationalDisposition(write) != reliablesubmit.OperationalApplied {
				t.Fatalf("held process result: operation=%d write=%d", operation, write)
			}
			if next != nil {
				assertOperationalCompleted(t, f, next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "the generation that replaced it")
			}
		})
	}
}

// operationalEndedCall is one call whose context a hook ends part way. at is
// the stored state when the context ended, entered whether the final sender
// entry had been reached by then.
// operationalExpiringContext is a context with a deadline that a test lets
// pass at a point of its choosing. Until then it is live. From then on it is
// done and reports context.DeadlineExceeded, as a context made by
// context.WithDeadline does once its time has come.
type operationalExpiringContext struct {
	context.Context
	deadline time.Time
	done     chan struct{}
	expired  atomic.Bool
}

func newOperationalExpiringContext() *operationalExpiringContext {
	return &operationalExpiringContext{Context: context.Background(), deadline: time.Now().Add(time.Hour), done: make(chan struct{})}
}

func (c *operationalExpiringContext) Deadline() (time.Time, bool) { return c.deadline, true }

func (c *operationalExpiringContext) Done() <-chan struct{} { return c.done }

func (c *operationalExpiringContext) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *operationalExpiringContext) expire() {
	if c.expired.CompareAndSwap(false, true) {
		close(c.done)
	}
}

type operationalEndedCall struct {
	f       *operationalFixture
	d       *operationalDomain
	ctx     context.Context
	cancel  context.CancelFunc
	ended   bool
	entered bool
	at      operationalPrestageState
	end     func()
}

// operationalEndableCall prepares a call at the given starting state: zero is
// a first delivery, any other value the state operationalSeedAt leaves.
func operationalEndableCall(t *testing.T, seed reliablesubmit.OperationalOperation) *operationalEndedCall {
	t.Helper()
	c := &operationalEndedCall{}
	if seed == 0 {
		c.f = makeOperationalFixture(t, "")
	} else {
		c.f, _, _ = operationalSeedAt(t, seed)
	}
	c.d = c.f.reopen()
	c.ctx, c.cancel = context.WithCancel(context.Background())
	t.Cleanup(c.cancel)
	reached := false
	c.d.proof = &operationalHandoffProofHooks{beforeEntrySample: func() { reached = true }}
	c.at = operationalPrestageStateAt(t, c.f)
	c.end = func() {
		if !c.ended {
			c.ended, c.entered = true, reached
			c.at = operationalPrestageStateAt(t, c.f)
			c.cancel()
		}
	}
	return c
}

func (c *operationalEndedCall) run() operationalHandoffResult {
	return c.f.service.handoffOperational(c.ctx, c.d, c.d.caller, c.f.raw)
}

// assertCanceled checks the answer of a call whose context ended: the reason,
// nothing written or sent after the end, and no run or receipt unless the
// call had already reached the final sender entry, where a cancellation alone
// returns the stored run.
func (c *operationalEndedCall) assertCanceled(t *testing.T, out operationalHandoffResult) {
	t.Helper()
	after := operationalPrestageStateAt(t, c.f)
	if c.ctx.Err() == nil || out.reason != reliablesubmit.OperationalCanceled || out.receipt.Valid() || after != c.at {
		t.Fatalf("cancelled call: %s ended=%t at=%+v after=%+v", operationalResultText(out), c.ctx.Err() != nil, c.at, after)
	}
	if c.entered {
		if out.kind != operationalAmbiguous || out.run == "" || !c.at.Marker {
			t.Fatalf("cancelled at the sender entry: %s at=%+v", operationalResultText(out), c.at)
		}
		return
	}
	if out.kind != operationalUnavailable || out.run != "" {
		t.Fatalf("cancelled before the sender entry: %s at=%+v", operationalResultText(out), c.at)
	}
}

// A2-8. A call whose context has ended answers OperationalCanceled wherever
// the admission returned no refusal of its own: the store refuses every read,
// binding and writer turn of an ended call, so the failed step reports the
// cancellation and not Unavailable or Integrity. Nothing is written or sent
// after the context ended.
func TestOperationalAdmissionCancelledCallAnswersCanceled(t *testing.T) {
	starts := []struct {
		name string
		seed reliablesubmit.OperationalOperation
	}{
		{"first delivery", 0},
		{"after establishment", reliablesubmit.OperationalEstablish},
		{"after run assignment", reliablesubmit.OperationalAssign},
		{"after intent", reliablesubmit.OperationalIntent},
	}
	t.Run("while EGS answers the confirmation", func(t *testing.T) {
		for _, start := range starts {
			t.Run(start.name, func(t *testing.T) {
				c := operationalEndableCall(t, start.seed)
				before := c.f.egs.count()
				// The handler runs on another goroutine; no write precedes
				// the confirmation, so the state before the call stands.
				c.f.egs.observe(c.cancel)
				out := c.run()
				c.assertCanceled(t, out)
				if c.f.egs.count() != before+1 {
					t.Fatalf("cancelled confirmation: trust requests=%d, want %d", c.f.egs.count(), before+1)
				}
				// A retry refuses at its pre-check, before any writer turn.
				if start.seed != 0 && (out.operation != 0 || out.write != 0) {
					t.Fatalf("cancelled confirmation of a retry: %s", operationalResultText(out))
				}
			})
		}
		t.Run("control: an unreadable admission row under a live context is Unavailable", func(t *testing.T) {
			c := operationalEndableCall(t, reliablesubmit.OperationalAssign)
			if _, err := c.f.db.Exec("DROP TABLE reliable_submit_operational_admission"); err != nil {
				t.Fatal(err)
			}
			before := operationalPrestageStateAt(t, c.f)
			out := c.run()
			if c.ctx.Err() != nil {
				t.Fatal("the control must not end the context")
			}
			assertOperationalRefusal(t, c.f, before, out, reliablesubmit.OperationalUnavailable)
		})
	})
	t.Run("at every freshness sample", func(t *testing.T) {
		for _, start := range starts {
			t.Run(start.name, func(t *testing.T) {
				ended := 0
				for k := 1; ; k++ {
					c := operationalEndableCall(t, start.seed)
					samples := 0
					operationalHooks(c.f.service).skew = func() time.Duration {
						if samples++; samples == k {
							c.end()
						}
						return 0
					}
					out := c.run()
					if samples < k {
						// The call takes fewer samples than k: it was not
						// ended and completes.
						assertOperationalCompleted(t, c.f, out, "a call that is not cancelled")
						break
					}
					c.assertCanceled(t, out)
					ended++
				}
				if ended == 0 {
					t.Fatal("no sample ended the context")
				}
			})
		}
	})
	t.Run("during the evaluation", func(t *testing.T) {
		for _, start := range starts[1:] {
			t.Run(start.name, func(t *testing.T) {
				ended := 0
				for k := 1; ; k++ {
					c := operationalEndableCall(t, start.seed)
					evaluations := 0
					operationalHooks(c.f.service).evaluated = func(allowed bool) {
						if !allowed {
							t.Errorf("evaluation %d refused a claim the rules allow", evaluations+1)
						}
						if evaluations++; evaluations == k {
							c.end()
						}
					}
					out := c.run()
					if evaluations < k {
						assertOperationalCompleted(t, c.f, out, "a call that is not cancelled")
						break
					}
					c.assertCanceled(t, out)
					// The first evaluation of a retry is the pre-check's. A
					// cancellation during it requests no writer turn.
					if k == 1 && (out.operation != 0 || out.write != 0) {
						t.Fatalf("cancelled during the pre-check's evaluation: %s", operationalResultText(out))
					}
					ended++
				}
				if ended == 0 {
					t.Fatal("no evaluation ended the context")
				}
			})
		}
	})
	// The bindings between the cuts have no sample of their own. Each one is
	// refused by the store once the context has ended.
	t.Run("before the staged tree is bound to the stamp", func(t *testing.T) {
		c := operationalEndableCall(t, reliablesubmit.OperationalIntent)
		c.d.proof.beforeStamp = c.end
		out := c.run()
		c.assertCanceled(t, out)
		// The stage this call created stays as charged residue, whatever
		// stopped the call: the claim cannot stage again.
		if !c.ended || c.at.Revision != 3 || c.at.StageEntries != 1 || c.at.Stamp || out.operation != 0 || out.write != 0 {
			t.Fatalf("cancelled before the stamp: %s at=%+v", operationalResultText(out), c.at)
		}
		again := c.f.submit()
		if after := operationalPrestageStateAt(t, c.f); again.reason != reliablesubmit.OperationalOccupiedReason ||
			again.receipt.Valid() || after != c.at {
			t.Fatalf("retry after a cancelled staging: %s before=%+v after=%+v", operationalResultText(again), c.at, after)
		}
	})
	t.Run("before the marker is bound", func(t *testing.T) {
		c := operationalEndableCall(t, reliablesubmit.OperationalIntent)
		c.d.proof.beforeMarker = c.end
		out := c.run()
		c.assertCanceled(t, out)
		if !c.ended || c.at.Revision != 4 || !c.at.Stamp || c.at.Marker ||
			out.operation != reliablesubmit.OperationalStamp || out.write != reliablesubmit.OperationalApplied {
			t.Fatalf("cancelled before the marker: %s at=%+v", operationalResultText(out), c.at)
		}
	})
	t.Run("before an accepted receipt is verified", func(t *testing.T) {
		c := operationalEndableCall(t, 0)
		first := c.f.submit()
		assertOperationalCompleted(t, c.f, first, "the first delivery")
		c.d.proof.beforeReceipt = c.end
		out := c.run()
		c.entered = false // the entry belongs to the first call
		c.assertCanceled(t, out)
		if !c.ended || !c.at.Receipt || out.operation != 0 || out.write != 0 {
			t.Fatalf("cancelled before the receipt: %s at=%+v", operationalResultText(out), c.at)
		}
		again := c.f.submit()
		assertOperationalCompleted(t, c.f, again, "the retry after the cancelled call")
		if again.run != first.run || !again.receipt.Equal(first.receipt) {
			t.Fatal("the retry after the cancelled call returned another run or receipt")
		}
	})
	t.Run("before a completed observation is bound", func(t *testing.T) {
		c := operationalEndableCall(t, 0)
		c.d.proof.beforeObservation = c.end
		out := c.run()
		// The marker is durable and the request was sent: as at the sender
		// entry, a cancellation alone keeps the stored run.
		c.assertCanceled(t, out)
		if !c.ended || !c.entered || c.at.Revision != 5 || c.at.Posts != 1 || c.at.Receipt ||
			out.operation != reliablesubmit.OperationalMark || out.write != reliablesubmit.OperationalMarkerDirect {
			t.Fatalf("cancelled before the observation was bound: %s at=%+v", operationalResultText(out), c.at)
		}
		again := c.f.submit()
		assertOperationalCompleted(t, c.f, again, "the retry after the cancelled call")
		if again.run != out.run {
			t.Fatal("the retry after the cancelled call returned another run")
		}
	})
	// The fourth point where an ended call keeps the stored run: the marker
	// is durable, the request was sent, and the context ends while the
	// provider is asked about the job. This point alone tells a deadline from
	// a cancellation, because the exchange reports which of the two ended it.
	t.Run("during the observation of the job", func(t *testing.T) {
		t.Run("cancelled", func(t *testing.T) {
			c := operationalEndableCall(t, 0)
			provider := c.d.provider
			gets := 0
			provider.exchangeEntry = func(method string) {
				if method == http.MethodGet {
					gets++
					c.end()
				}
			}
			defer func() { provider.exchangeEntry = nil }()
			out := c.run()
			provider.exchangeEntry = nil
			c.assertCanceled(t, out)
			if !c.ended || !c.entered || gets != 1 || c.at.Revision != 5 || c.at.Posts != 1 || c.at.Receipt ||
				out.operation != reliablesubmit.OperationalMark || out.write != reliablesubmit.OperationalMarkerDirect {
				t.Fatalf("cancelled during the observation: %s gets=%d at=%+v", operationalResultText(out), gets, c.at)
			}
			again := c.f.submit()
			assertOperationalCompleted(t, c.f, again, "the retry after the cancelled call")
			if again.run != out.run {
				t.Fatal("the retry after the cancelled call returned another run")
			}
		})
		t.Run("deadline passed", func(t *testing.T) {
			c := operationalEndableCall(t, 0)
			// The provider's answer is held back until the caller is gone, so
			// the exchange cannot complete before the passed deadline reaches
			// the request.
			setMode := func(mode string) {
				c.f.receiver.mu.Lock()
				defer c.f.receiver.mu.Unlock()
				c.f.receiver.mode = mode
			}
			setMode("observation-timeout")
			ctx := newOperationalExpiringContext()
			provider := c.d.provider
			gets := 0
			var at operationalPrestageState
			provider.exchangeEntry = func(method string) {
				if method == http.MethodGet {
					gets++
					at = operationalPrestageStateAt(t, c.f)
					ctx.expire()
				}
			}
			defer func() { provider.exchangeEntry = nil }()
			started := time.Now()
			out := c.f.service.handoffOperational(ctx, c.d, c.d.caller, c.f.raw)
			elapsed := time.Since(started)
			provider.exchangeEntry = nil
			after := operationalPrestageStateAt(t, c.f)
			// Whether the provider saw the request before the passed deadline
			// reached it is not fixed; nothing else may differ.
			after.Gets = at.Gets
			// The provider bounds the exchange by itself after five seconds and
			// reports that as a timeout too. This answer came earlier.
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) || elapsed >= 4*time.Second || gets != 1 {
				t.Fatalf("the deadline did not end the exchange: err=%v elapsed=%s gets=%d", ctx.Err(), elapsed, gets)
			}
			if out.kind != operationalAmbiguous || out.reason != reliablesubmit.OperationalTimeout || out.run == "" || out.receipt.Valid() ||
				out.operation != reliablesubmit.OperationalMark || out.write != reliablesubmit.OperationalMarkerDirect {
				t.Fatalf("deadline passed during the observation: %s", operationalResultText(out))
			}
			if after != at || at.Revision != 5 || !at.Marker || at.Posts != 1 || at.Receipt {
				t.Fatalf("deadline passed during the observation: at=%+v after=%+v", at, after)
			}
			setMode("")
			again := c.f.submit()
			assertOperationalCompleted(t, c.f, again, "the retry after the deadline")
			if again.run != out.run {
				t.Fatal("the retry after the deadline returned another run")
			}
		})
	})
	// Controls under a live context. The same steps fail for a reason of
	// their own and report that reason, so the cancellation is not the
	// answer of every binding that fails.
	t.Run("control: a staged tree that drifted before the marker is an integrity failure", func(t *testing.T) {
		c := operationalEndableCall(t, reliablesubmit.OperationalIntent)
		path := c.d.stage.path
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(path, info.Mode().Perm()); err != nil {
				t.Error(err)
			}
		})
		drifted := false
		c.d.proof.beforeMarker = func() {
			if err := os.Chmod(path, info.Mode().Perm()|0o020); err != nil {
				t.Fatal(err)
			}
			drifted = true
		}
		out := c.run()
		after := operationalPrestageStateAt(t, c.f)
		if !drifted || c.ctx.Err() != nil || out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalIntegrity ||
			out.run != "" || out.receipt.Valid() || after.Revision != 4 || !after.Stamp || after.Marker || after.Posts != 0 {
			t.Fatalf("drift before the marker under a live context: %s drifted=%t after=%+v", operationalResultText(out), drifted, after)
		}
	})
	t.Run("control: an accepted receipt that does not verify is an integrity failure", func(t *testing.T) {
		c := operationalEndableCall(t, 0)
		first := c.f.submit()
		assertOperationalCompleted(t, c.f, first, "the first delivery")
		// The receipt binds the provider's projection of the job, and the
		// region is part of that projection. The reopened domain shares the
		// fixture's provider, so the region is restored before the retry.
		provider := c.d.provider
		region := provider.realm.region
		provider.realm.region = region + "-other"
		reached := false
		c.d.proof.beforeReceipt = func() { reached = true }
		out := c.run()
		provider.realm.region = region
		if !reached || c.ctx.Err() != nil || out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalIntegrity ||
			out.run != "" || out.receipt.Valid() {
			t.Fatalf("a receipt that does not verify under a live context: %s reached=%t", operationalResultText(out), reached)
		}
		again := c.f.submit()
		assertOperationalCompleted(t, c.f, again, "the retry with the provider's own region")
		if again.run != first.run || !again.receipt.Equal(first.receipt) {
			t.Fatal("the retry returned another run or receipt")
		}
	})
	t.Run("control: an observation that does not bind is an integrity failure", func(t *testing.T) {
		c := operationalEndableCall(t, 0)
		// The witness of the observation is made with this key, and the store
		// checks it with its own copy.
		key := &c.d.keys.key.bytes
		saved := *key
		t.Cleanup(func() { *key = saved })
		changed := false
		c.d.proof.beforeObservation = func() {
			key[0] ^= 1
			changed = true
		}
		out := c.run()
		*key = saved
		after := operationalPrestageStateAt(t, c.f)
		if !changed || c.ctx.Err() != nil || out.kind != operationalUnavailable || out.reason != reliablesubmit.OperationalIntegrity ||
			out.run != "" || out.receipt.Valid() || after.Revision != 5 || !after.Marker || after.Receipt || after.Posts != 1 {
			t.Fatalf("an observation that does not bind under a live context: %s changed=%t after=%+v", operationalResultText(out), changed, after)
		}
	})
}

// operationalRefusingFromPolicy allows a claim until evaluation number from of
// one call and refuses it from then on. It stands for rules that refuse a
// retained claim at one chosen evaluation: the pre-check's, a cut's, or the one
// after a cut has committed.
type operationalRefusingFromPolicy struct {
	evaluations *int
	from        int
}

func (operationalRefusingFromPolicy) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return nil
}

func (p operationalRefusingFromPolicy) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	if *p.evaluations++; *p.evaluations >= p.from {
		return DenyAdmissionPolicyDecision("test-refusal", "test-refusal", "refused by the test policy")
	}
	return AllowAdmissionPolicyDecision()
}

// A3-2. The admission's own judgment wins over a cancellation. A refusal that
// the judgment of a retained claim returned is reported as OperationalDenied
// also when the context of the call ended while that judgment ran: at the
// pre-check, inside a cut, and after a cut has committed. The run and the
// receipt are withheld, and nothing is written or sent after the end. The
// answer is the one the same refusal gets under a live context.
func TestOperationalAdmissionDenialUnderAnEndedContextAnswersDenied(t *testing.T) {
	t.Run("an evaluation that refuses", func(t *testing.T) {
		for _, start := range []struct {
			name string
			seed reliablesubmit.OperationalOperation
		}{
			{"after run assignment", reliablesubmit.OperationalAssign},
			{"after intent", reliablesubmit.OperationalIntent},
		} {
			t.Run(start.name, func(t *testing.T) {
				// attempt makes evaluation number k of one call refuse. With
				// end set, the hook of that evaluation ends the context before
				// the refusal is returned.
				attempt := func(k int, end bool) (*operationalEndedCall, int, operationalHandoffResult, operationalPrestageState) {
					c := operationalEndableCall(t, start.seed)
					evaluations := 0
					operationalHooks(c.f.service).stricter = operationalRefusingFromPolicy{evaluations: &evaluations, from: k}
					operationalHooks(c.f.service).evaluated = func(allowed bool) {
						if allowed == (evaluations >= k) {
							t.Errorf("evaluation %d of a claim refused from evaluation %d: allowed=%t", evaluations, k, allowed)
						}
						if !allowed && end {
							c.end()
						}
					}
					out := c.run()
					return c, evaluations, out, operationalPrestageStateAt(t, c.f)
				}
				preChecks, cuts, afterCommits := 0, 0, 0
				for k := 1; ; k++ {
					c, evaluations, out, after := attempt(k, true)
					if evaluations < k {
						// The call makes fewer evaluations than k: nothing
						// refused it and it completes.
						assertOperationalCompleted(t, c.f, out, "a call that no evaluation refuses")
						break
					}
					if evaluations != k || !c.ended || c.ctx.Err() == nil {
						t.Fatalf("evaluation %d did not refuse and end the call: evaluations=%d ended=%t", k, evaluations, c.ended)
					}
					if out.reason != reliablesubmit.OperationalDenied || out.kind != operationalUnavailable || out.run != "" ||
						out.receipt.Valid() || after != c.at || after.Posts != 0 {
						t.Fatalf("refused at evaluation %d under an ended context: %s at=%+v after=%+v", k, operationalResultText(out), c.at, after)
					}
					live, liveEvaluations, control, liveAfter := attempt(k, false)
					if live.ended || live.ctx.Err() != nil || liveEvaluations != k {
						t.Fatalf("control at evaluation %d: ended=%t evaluations=%d", k, live.ended, liveEvaluations)
					}
					if control.reason != out.reason || control.kind != out.kind || control.operation != out.operation ||
						control.write != out.write || control.run != "" || control.receipt.Valid() || liveAfter != after {
						t.Fatalf("evaluation %d: ended context %s after=%+v, live context %s after=%+v", k,
							operationalResultText(out), after, operationalResultText(control), liveAfter)
					}
					switch {
					case out.operation == 0 && out.write == 0:
						preChecks++
					case out.write == 0:
						cuts++
					default:
						afterCommits++
					}
					// The first evaluation of a retry is the pre-check's.
					if k == 1 && (out.operation != 0 || out.write != 0) {
						t.Fatalf("refused at the pre-check: %s", operationalResultText(out))
					}
				}
				if preChecks == 0 || cuts == 0 || afterCommits == 0 {
					t.Fatalf("refusals reached: %d outside a cut, %d inside a cut, %d after a cut committed", preChecks, cuts, afterCommits)
				}
			})
		}
	})
	// The two refusals before the evaluation have no hook of their own. The
	// context is ended at the freshness sample that precedes them in the same
	// judgment, after the judgment has looked at the context on entry.
	endingAtSample := func(t *testing.T, proof *operationalAdmissionProofHooks) (context.Context, *int) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		samples := 0
		proof.skew = func() time.Duration {
			samples++
			cancel()
			return 0
		}
		return ctx, &samples
	}
	t.Run("a refusal by the trust content", func(t *testing.T) {
		f := operationalSeedIntent(t)
		original := operationalV2Original(t, f)
		proof := &operationalAdmissionProofHooks{}
		service := operationalProofService(t, f, func(s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				original.resolved.plan.artifactDigest)
			s.operationalProof = proof
		})
		service.confirmOperationalAdmission(context.Background())
		if reason := service.qualifyOperationalRetained(context.Background(), original, f.domain.realm); reason != reliablesubmit.OperationalDenied {
			t.Fatalf("control under a live context: reason=%d", reason)
		}
		ctx, samples := endingAtSample(t, proof)
		if reason := service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalDenied ||
			ctx.Err() == nil || *samples == 0 {
			t.Fatalf("revoked artifact under an ended context: reason=%d ended=%t samples=%d", reason, ctx.Err() != nil, *samples)
		}
	})
	t.Run("a refusal by the verifier", func(t *testing.T) {
		f := operationalSeedIntent(t)
		original := operationalV2Original(t, f)
		var tampered evidencev1.ArtifactEvidence
		if err := json.Unmarshal([]byte(f.expectedEvidence), &tampered); err != nil {
			t.Fatal(err)
		}
		tampered.Seal.Signature = strings.Repeat("A", len(tampered.Seal.Signature))
		changed, err := json.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		original.resolved.provenanceRecord = string(changed)
		f.confirm()
		if reason := f.service.qualifyOperationalRetained(context.Background(), original, f.domain.realm); reason != reliablesubmit.OperationalDenied {
			t.Fatalf("control under a live context: reason=%d", reason)
		}
		ctx, samples := endingAtSample(t, operationalHooks(f.service))
		if reason := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalDenied ||
			ctx.Err() == nil || *samples == 0 {
			t.Fatalf("refused seal under an ended context: reason=%d ended=%t samples=%d", reason, ctx.Err() != nil, *samples)
		}
	})
	// The same ending with content that allows the claim is a cancellation: the
	// judgment returned no refusal of its own.
	t.Run("control: the same ending without a refusal is a cancellation", func(t *testing.T) {
		f := operationalSeedIntent(t)
		original := operationalV2Original(t, f)
		f.confirm()
		ctx, samples := endingAtSample(t, operationalHooks(f.service))
		if reason := f.service.qualifyOperationalRetained(ctx, original, f.domain.realm); reason != reliablesubmit.OperationalCanceled ||
			ctx.Err() == nil || *samples == 0 {
			t.Fatalf("allowed claim under an ended context: reason=%d ended=%t samples=%d", reason, ctx.Err() != nil, *samples)
		}
	})
}

// ---- The admission state package, with real tokens ----

// operationalStateField returns an unexported field of the admission state as
// a value a test may set. The fields live in the package admissionstate, so no
// code here can name them: reflection turns the address of the field into a
// settable value. A production file needs the reflect or the unsafe import for
// the same, and the guard pins both.
func operationalStateField(t *testing.T, owner reflect.Value, name string) reflect.Value {
	t.Helper()
	field := owner.FieldByName(name)
	if !field.IsValid() || !field.CanAddr() {
		t.Fatalf("the admission state has no addressable field %q; rewrite the test that sets it", name)
	}
	return reflect.NewAt(field.Type(), field.Addr().UnsafePointer()).Elem()
}

// A Service from NewService owns the admission state it holds: the state is
// open for the first view of exactly that Service. Every other test here
// builds its Service by hand, so this is the one test of that assignment.
func TestOperationalAdmissionNewServiceOwnsItsState(t *testing.T) {
	workspace := physicalTestTempDir(t)
	cfg := newExecutionRootStartupTestConfig(t, filepath.Join(workspace, "stage"), filepath.Join(workspace, "results"))
	cfg.Nomad = esconfig.NomadConfig{}
	cfg.Execution = esconfig.ExecutionConfig{}
	service, err := NewService(cfg)
	if err != nil || service == nil {
		t.Fatalf("control: a prepare-only Service was not constructed: %v", err)
	}
	if !service.operational.Installable(service) || service.operational.Commissioned() ||
		service.operational.Inspect(service) != (admissionstate.Status{}) {
		t.Fatal("NewService did not give its Service an open admission state of its own")
	}
	// Another Service that holds the same handle is not its owner, and a
	// second Service gets a state of its own.
	other := &Service{operational: service.operational}
	if other.operational.Installable(other) {
		t.Fatal("the state of one Service is open to another that holds its handle")
	}
	second, err := NewService(cfg)
	if err != nil || second == nil {
		t.Fatalf("control: a second Service was not constructed: %v", err)
	}
	if second.operational == service.operational || !second.operational.Installable(second) ||
		second.operational.Installable(service) || service.operational.Installable(second) {
		t.Fatal("two Services from NewService do not each own a state")
	}
}

// A token that names a realm and a digest comes only from the store, so the
// package admissionstate cannot test its own Install and its confirmation of
// equal content. This test does, with the token and the content of the
// fixture's commissioned view, on states of its own.
func TestOperationalAdmissionState(t *testing.T) {
	f := makeOperationalFixture(t, "")
	realm := f.domain.realm
	held := operationalInstalledView(f.service)
	token, content := held.Token(), operationalViewContent(held)
	digest, ok := admissionstate.Digest(content)
	if !ok || !token.Names(realm.installation, realm.epoch, digest) {
		t.Fatal("control: the fixture's token does not name its realm and content")
	}
	type owned struct {
		owner *Service
		state admissionstate.State
	}
	newOwned := func() owned {
		owner := &Service{}
		return owned{owner, admissionstate.New(owner)}
	}
	untouched := func(t *testing.T, o owned, what string) {
		t.Helper()
		if got := o.state.Inspect(o.owner); got != (admissionstate.Status{}) || !o.state.Installable(o.owner) || o.state.Commissioned() {
			t.Fatalf("%s: a refused install changed the state: %+v", what, got)
		}
	}
	t.Run("a view that its token names is installed once", func(t *testing.T) {
		o := newOwned()
		type marker struct{ n int }
		proof := &marker{1}
		if !o.state.Install(o.owner, realm.installation, realm.epoch, token, content, proof, nil) {
			t.Fatal("the store's own token and content were refused")
		}
		status := o.state.Inspect(o.owner)
		if !status.View.Installed() || status.View.Token() != token || status.View.Proof() != any(proof) ||
			!reflect.DeepEqual(operationalViewContent(status.View), content) || status.Withdrawn || status.Superseded ||
			!status.Confirmed.IsZero() || o.state.Installable(o.owner) || !o.state.Commissioned() {
			t.Fatalf("status after install: %+v", status)
		}
		if _, ok := o.state.Current(o.owner, realm.installation, realm.epoch); ok {
			t.Fatal("a view is current before its first confirmation")
		}
		// A second view is refused, with the same token and content and with
		// those of a later generation.
		later := operationalProofService(t, f, func(s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				"sha256:"+strings.Repeat("e", 64))
		})
		next := operationalInstalledView(later)
		if next.Token() == token {
			t.Fatal("control: the later generation carries the same token")
		}
		if o.state.Install(o.owner, realm.installation, realm.epoch, token, content, nil, nil) ||
			o.state.Install(o.owner, realm.installation, realm.epoch, next.Token(), operationalViewContent(next), nil, nil) ||
			o.state.Inspect(o.owner).View != status.View {
			t.Fatal("a second view was installed")
		}
		// Control: the later token and content are a pair a fresh state takes.
		if other := newOwned(); !other.state.Install(other.owner, realm.installation, realm.epoch, next.Token(), operationalViewContent(next), nil, nil) {
			t.Fatal("control: the later generation's own token and content were refused")
		}
	})
	t.Run("what the token does not name is refused", func(t *testing.T) {
		otherInstallation := realm.installation
		otherInstallation[0] ^= 0xff
		changed := func(change func(*admissionstate.Content)) admissionstate.Content {
			c := operationalViewContent(held)
			change(&c)
			return c
		}
		for name, tc := range map[string]struct {
			installation [32]byte
			epoch        uint64
			token        reliablesubmit.OperationalAdmissionToken
			content      admissionstate.Content
		}{
			"another installation": {otherInstallation, realm.epoch, token, content},
			"a later epoch":        {realm.installation, realm.epoch + 1, token, content},
			"no installation":      {[32]byte{}, realm.epoch, token, content},
			"epoch zero":           {realm.installation, 0, token, content},
			"no token":             {realm.installation, realm.epoch, reliablesubmit.OperationalAdmissionToken{}, content},
			"another allowed signer": {realm.installation, realm.epoch, token, changed(func(c *admissionstate.Content) {
				c.Trust.SignerPolicy.AllowedSigners = append(c.Trust.SignerPolicy.AllowedSigners, "one-more-signer")
			})},
			"another verifier key": {realm.installation, realm.epoch, token, changed(func(c *admissionstate.Content) {
				c.Verifier.PublicKey[0] ^= 1
			})},
			"another policy": {realm.installation, realm.epoch, token, changed(func(c *admissionstate.Content) {
				c.Policies = append(c.Policies, admissionstate.Policy{ID: string(configuredStaticScriptLiteralDenyPolicyID),
					Entries: []admissionstate.PolicyEntry{{ID: "added", Literal: "added"}}})
			})},
			"content without a digest": {realm.installation, realm.epoch, token, changed(func(c *admissionstate.Content) {
				c.Policies = nil
			})},
		} {
			t.Run(name, func(t *testing.T) {
				o := newOwned()
				if o.state.Install(o.owner, tc.installation, tc.epoch, tc.token, tc.content, nil, nil) {
					t.Fatal("installed")
				}
				untouched(t, o, name)
			})
		}
		t.Run("another owner and no owner", func(t *testing.T) {
			o := newOwned()
			if o.state.Install(&Service{}, realm.installation, realm.epoch, token, content, nil, nil) ||
				o.state.Install(nil, realm.installation, realm.epoch, token, content, nil, nil) ||
				(admissionstate.State{}).Install(o.owner, realm.installation, realm.epoch, token, content, nil, nil) {
				t.Fatal("installed")
			}
			untouched(t, o, "another owner")
		})
	})
	t.Run("a latched state without a view takes none", func(t *testing.T) {
		// No method leaves a state latched without a view. Should it ever
		// happen, Install refuses on the latch alone, with a token and content
		// that an open state takes.
		for _, latch := range []string{"withdrawn", "superseded"} {
			t.Run(latch, func(t *testing.T) {
				o := newOwned()
				state := operationalStateField(t, reflect.ValueOf(&o.state).Elem(), "s").Elem()
				lock := operationalStateField(t, state, "mu").Addr().Interface().(*sync.RWMutex)
				set := func(value bool) {
					lock.Lock()
					defer lock.Unlock()
					operationalStateField(t, state, latch).SetBool(value)
				}
				set(true)
				if o.state.Installable(o.owner) {
					t.Fatal("a latched state is open")
				}
				if o.state.Install(o.owner, realm.installation, realm.epoch, token, content, nil, nil) ||
					o.state.Inspect(o.owner).View.Installed() {
					t.Fatal("a latched state without a view took one")
				}
				// The control: without the latch the same call installs.
				set(false)
				if !o.state.Install(o.owner, realm.installation, realm.epoch, token, content, nil, nil) {
					t.Fatal("control: the same state without its latch refused the view")
				}
			})
		}
	})
	t.Run("the installed content is the state's own copy", func(t *testing.T) {
		o := newOwned()
		given := operationalViewContent(held)
		if !o.state.Install(o.owner, realm.installation, realm.epoch, token, given, nil, nil) {
			t.Fatal("control: install refused")
		}
		given.Trust.SignerPolicy.AllowedSigners[0] = "written-after-install"
		given.Verifier.PublicKey[0] ^= 0xff
		given.Policies[0].ID = "written-after-install"
		if got := operationalViewContent(o.state.Inspect(o.owner).View); !reflect.DeepEqual(got, content) {
			t.Fatal("a write to the caller's content reached the installed view")
		}
	})
	t.Run("confirmation, deadline and latches", func(t *testing.T) {
		o := newOwned()
		var skew time.Duration
		if !o.state.Install(o.owner, realm.installation, realm.epoch, token, content, nil, func() time.Duration { return skew }) {
			t.Fatal("control: install refused")
		}
		view, ok := o.state.Confirmable(o.owner)
		if !ok || view != o.state.Inspect(o.owner).View {
			t.Fatal("an installed view is not confirmable")
		}
		current := func() bool {
			got, ok := o.state.Current(o.owner, realm.installation, realm.epoch)
			if ok != got.Installed() || (ok && got != view) {
				t.Fatal("Current returned a view it refused, or another view")
			}
			return ok
		}
		first := time.Now()
		// Equal trust in another order is equal content.
		reordered := operationalViewContent(view).Trust
		for i, j := 0, len(reordered.SignerPolicy.AllowedSigners)-1; i < j; i, j = i+1, j-1 {
			reordered.SignerPolicy.AllowedSigners[i], reordered.SignerPolicy.AllowedSigners[j] =
				reordered.SignerPolicy.AllowedSigners[j], reordered.SignerPolicy.AllowedSigners[i]
		}
		o.state.Confirm(o.owner, view, reordered, first)
		if got := o.state.Inspect(o.owner); !got.Confirmed.Equal(first) || got.Superseded || !current() {
			t.Fatalf("equal trust did not confirm the view: %+v", got)
		}
		// The time only moves forward.
		o.state.Confirm(o.owner, view, content.Trust, first.Add(-time.Second))
		if got := o.state.Inspect(o.owner); !got.Confirmed.Equal(first) {
			t.Fatal("an earlier confirmation moved the time back")
		}
		second := time.Now()
		for !second.After(first) {
			second = time.Now()
		}
		o.state.Confirm(o.owner, view, content.Trust, second)
		if got := o.state.Inspect(o.owner); !got.Confirmed.Equal(second) {
			t.Fatal("a later confirmation did not move the time forward")
		}
		// The deadline through the proof seam, and back.
		skew = admissionstate.ConfirmationLimit
		if current() {
			t.Fatal("a view past its deadline is current")
		}
		skew = 0
		if !current() {
			t.Fatal("control: the view is not current again")
		}
		// Other trust latches, and equal trust does not open the state again.
		other := operationalViewContent(view).Trust
		other.SignerPolicy.RevokedSigners = append(other.SignerPolicy.RevokedSigners, "an-unrelated-signer")
		o.state.Confirm(o.owner, view, other, time.Now())
		if got := o.state.Inspect(o.owner); !got.Superseded || !got.Confirmed.Equal(second) || current() {
			t.Fatalf("other trust did not latch supersession: %+v", got)
		}
		o.state.Confirm(o.owner, view, content.Trust, time.Now())
		if _, ok := o.state.Confirmable(o.owner); ok || current() || !o.state.Inspect(o.owner).Superseded {
			t.Fatal("equal trust opened a superseded state again")
		}
		// Withdrawal returns the token to withdraw in the store.
		if got, ok := o.state.Withdraw(o.owner, realm.installation, realm.epoch); !ok || got != token {
			t.Fatal("withdrawal refused, or it returned another token")
		}
		if got := o.state.Inspect(o.owner); !got.Withdrawn || !got.Superseded || got.View != view || o.state.Installable(o.owner) {
			t.Fatalf("status after withdrawal: %+v", got)
		}
	})
	// The third audit saved the latches of a Service before a withdrawal and
	// wrote them back after it. What a Service can save now is its handle,
	// and a handle names the state: it holds no latch and no view of its own.
	t.Run("a handle put back restores nothing", func(t *testing.T) {
		ctx := context.Background()
		for _, stop := range []struct {
			name string
			stop func(t *testing.T, g *operationalFixture)
			want func(admissionstate.Status) bool
		}{
			{"after a withdrawal", func(t *testing.T, g *operationalFixture) {
				if !g.service.withdrawOperationalEffects(ctx, g.domain) {
					t.Fatal("withdrawal unavailable")
				}
			}, func(status admissionstate.Status) bool { return status.Withdrawn && !status.Superseded }},
			{"after a supersession", func(t *testing.T, g *operationalFixture) {
				trust := operationalInstalledView(g.service).Trust()
				trust.SignerPolicy.RevokedSigners = append(trust.SignerPolicy.RevokedSigners, "an-unrelated-signer")
				g.egs.serve(trust)
				g.service.confirmOperationalAdmission(ctx)
			}, func(status admissionstate.Status) bool { return status.Superseded && !status.Withdrawn }},
		} {
			t.Run(stop.name, func(t *testing.T) {
				g := makeOperationalFixture(t, "")
				g.confirm()
				realm := g.domain.realm
				current := func() bool {
					_, ok := g.service.currentOperationalAdmission(realm)
					return ok
				}
				saved, view := g.service.operational, operationalInstalledView(g.service)
				if !current() {
					t.Fatal("control: the fixture's view is not current")
				}
				stop.stop(t, g)
				if current() {
					t.Fatal("control: the view is current after the stop")
				}
				g.service.operational = saved
				if status := g.service.operational.Inspect(g.service); current() || !stop.want(status) || status.View != view {
					t.Fatalf("the handle saved before the stop reopened the state: %+v", status)
				}
				// The other handles a Service can put in place of its own hold
				// no view: the zero handle, and a new state. With a new state
				// the process is one that was restarted, and it is judged like
				// one.
				row := operationalAdmissionRowAt(t, g)
				g.service.operational = admissionstate.State{}
				if current() || g.service.commissionOperationalAdmission(ctx, g.domain) == nil ||
					g.service.advanceOperationalAdmission(ctx, g.domain, row.Generation) == nil || operationalAdmissionRowAt(t, g) != row {
					t.Fatal("a Service with the zero handle is current or was commissioned")
				}
				g.service.operational = admissionstate.New(g.service)
				if current() {
					t.Fatal("a Service with a new state is current")
				}
				err := g.service.commissionOperationalAdmission(ctx, g.domain)
				if row.State != 1 {
					// The withdrawal is durable: the row refuses the same content
					// again, by joining and by advancing.
					if err == nil || g.service.advanceOperationalAdmission(ctx, g.domain, row.Generation) == nil ||
						operationalInstalledView(g.service).Installed() || operationalAdmissionRowAt(t, g) != row {
						t.Fatalf("a new state was commissioned on a withdrawn domain: %v", err)
					}
					return
				}
				// The supersession was this process's own finding and the row is
				// still enabled, so the new state joins it like a restarted
				// process. It admits nothing before its confirmation, and the
				// confirmation finds what the old state found.
				if err != nil || !operationalInstalledView(g.service).Installed() || current() || operationalAdmissionRowAt(t, g) != row {
					t.Fatalf("a new state did not join the enabled row like a restarted process: %v", err)
				}
				g.service.confirmOperationalAdmission(ctx)
				if status := g.service.operational.Inspect(g.service); current() || !status.Superseded {
					t.Fatalf("a new state was confirmed against trust that differs: %+v", status)
				}
			})
		}
	})
}

// operationalServiceWithViewByHand makes a Service that holds nothing but an
// admission state with one installed and confirmed view. The token must be one
// the store issued for the realm and the content; proof is the seam value the
// view carries, nil for none.
func operationalServiceWithViewByHand(t *testing.T, realm operationalRealm, token reliablesubmit.OperationalAdmissionToken,
	content admissionstate.Content, proof *operationalAdmissionProofHooks) *Service {
	t.Helper()
	owner := &Service{}
	owner.operational = admissionstate.New(owner)
	var seam any
	if proof != nil {
		seam = proof
	}
	if !owner.operational.Install(owner, realm.installation, realm.epoch, token, content, seam, nil) {
		t.Fatal("the store's token and the content it names were refused")
	}
	view, ok := owner.operational.Confirmable(owner)
	if !ok {
		t.Fatal("the installed view cannot be confirmed")
	}
	owner.operational.Confirm(owner, view, view.Trust(), time.Now())
	if current, ok := owner.currentOperationalAdmission(realm); !ok || current != view {
		t.Fatal("the confirmed view is not current")
	}
	return owner
}

// The view holds its policies as plain content, and the set it enforces is
// built from that content for each judgment. The two directions are exact
// inverses on every set a Service can commission, and each refuses what the
// other cannot produce.
func TestOperationalAdmissionPolicyContent(t *testing.T) {
	selected := admissionPolicySet{policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{}}}
	entries := []configuredStaticScriptLiteralDenyEntry{{id: "rule-1", literal: "rm -rf /"}, {id: "rule-2", literal: "curl | sh"}}
	both := admissionPolicySet{policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{},
		configuredStaticScriptLiteralDenyPolicy{entries: entries}}}
	t.Run("the mapping covers every field of the built-in policies", func(t *testing.T) {
		// The content names a policy by its id and its entries by id and
		// literal. A new field in a built-in policy fails here until the
		// content, the digest and both directions cover it.
		for typ, want := range map[reflect.Type][]string{
			reflect.TypeOf(selectedDestructiveShellCommandPolicy{}):   nil,
			reflect.TypeOf(configuredStaticScriptLiteralDenyPolicy{}): {"entries"},
			reflect.TypeOf(configuredStaticScriptLiteralDenyEntry{}):  {"id", "literal"},
			reflect.TypeOf(admissionPolicySet{}):                      {"policies"},
		} {
			var got []string
			for i := 0; i < typ.NumField(); i++ {
				got = append(got, typ.Field(i).Name)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s fields are %v, want %v", typ, got, want)
			}
		}
	})
	t.Run("round trip", func(t *testing.T) {
		for name, set := range map[string]admissionPolicySet{"selected": selected, "selected and configured": both} {
			copied, ok := copyOperationalPolicySet(set)
			if !ok {
				t.Fatalf("%s: control: the set cannot be commissioned", name)
			}
			content, ok := operationalPolicyContent(copied)
			if !ok || len(content) != len(set.policies) || content[0].ID != string(selectedDestructiveShellCommandPolicyID) ||
				content[0].Entries != nil {
				t.Fatalf("%s: content=%+v ok=%t", name, content, ok)
			}
			built, ok := operationalPolicySet(content)
			if !ok || !reflect.DeepEqual(built, copied) || !operationalPolicyEquals(built, set) {
				t.Fatalf("%s: the set built from the content is not the set it names: %+v", name, built)
			}
			again, ok := operationalPolicyContent(built)
			if !ok || !reflect.DeepEqual(again, content) {
				t.Fatalf("%s: the content of the built set differs", name)
			}
		}
		content, _ := operationalPolicyContent(both)
		want := []admissionstate.Policy{{ID: "execution-substrate.admission.selected-destructive-shell-command/v1"},
			{ID: "execution-substrate.admission.configured-static-script-literal-deny/v1",
				Entries: []admissionstate.PolicyEntry{{ID: "rule-1", Literal: "rm -rf /"}, {ID: "rule-2", Literal: "curl | sh"}}}}
		if !reflect.DeepEqual(content, want) {
			t.Fatalf("content of the configured set: %+v", content)
		}
		// The content does not share the entries of the set, and the built set
		// does not share those of the content.
		content[1].Entries[0].Literal = "written"
		if entries[0].literal != "rm -rf /" {
			t.Fatal("the content aliases the entries of the set")
		}
		built, _ := operationalPolicySet(want)
		want[1].Entries[1].Literal = "written"
		if built.policies[1].(configuredStaticScriptLiteralDenyPolicy).entries[1].literal != "curl | sh" {
			t.Fatal("the built set aliases the entries of the content")
		}
	})
	// The digest of the content is the digest the function before the move
	// took over the set itself: a database written before is joined after.
	t.Run("the digest through the mapping is the digest before the move", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		trust := egscontract.RuntimeTrustPolicy{
			SignerPolicy:   egscontract.SignerPolicy{AllowedSigners: []string{"signer-a", "signer-b"}, RevokedSigners: []string{"signer-c"}},
			ArtifactPolicy: egscontract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.Repeat("0123456789abcdef", 4)}},
		}
		for name, tc := range map[string]struct {
			set  admissionPolicySet
			want string
		}{
			"selected":                {selected, "04560e9588865c202225325b34080e433ee6c9c840133499d783313c62d57f7d"},
			"selected and configured": {both, "b6e2de007cf008905d2855b504dd14ba697b300643b0096a966c17c18c9a0c48"},
		} {
			policies, ok := operationalPolicyContent(tc.set)
			digest, digestOK := admissionstate.Digest(admissionstate.Content{Trust: trust,
				Verifier: admissionstate.Verifier{Algorithm: "ed25519", KeyID: "key-1", PublicKey: key}, Policies: policies})
			if !ok || !digestOK || fmt.Sprintf("%x", digest) != tc.want {
				t.Fatalf("%s: digest=%x, want %s", name, digest, tc.want)
			}
		}
	})
	t.Run("a set that cannot be named has no content", func(t *testing.T) {
		for name, set := range map[string]admissionPolicySet{
			"no policy":                      {},
			"an unsupported policy":          {policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{}, &rejectAllPolicy{}}},
			"a nested set":                   {policies: []AdmissionPolicyEvaluator{selected}},
			"a pointer to a built-in policy": {policies: []AdmissionPolicyEvaluator{&selectedDestructiveShellCommandPolicy{}}},
		} {
			if content, ok := operationalPolicyContent(set); ok || content != nil {
				t.Fatalf("%s: content=%+v ok=%t", name, content, ok)
			}
		}
	})
	t.Run("content that no set produces builds no set", func(t *testing.T) {
		selectedID, configuredID := string(selectedDestructiveShellCommandPolicyID), string(configuredStaticScriptLiteralDenyPolicyID)
		entry := []admissionstate.PolicyEntry{{ID: "rule", Literal: "literal"}}
		for name, content := range map[string][]admissionstate.Policy{
			"no policy list":                                 nil,
			"empty policy list":                              {},
			"three policies":                                 {{ID: selectedID}, {ID: configuredID, Entries: entry}, {ID: configuredID, Entries: entry}},
			"an unknown id":                                  {{ID: selectedID}, {ID: "execution-substrate.admission.unknown/v1", Entries: entry}},
			"an empty id":                                    {{ID: ""}},
			"the selected policy with entries":               {{ID: selectedID, Entries: entry}},
			"the selected policy second":                     {{ID: selectedID}, {ID: selectedID}},
			"the configured policy first":                    {{ID: configuredID, Entries: entry}},
			"two configured policies":                        {{ID: configuredID, Entries: entry}, {ID: configuredID, Entries: entry}},
			"the configured policy without entries":          {{ID: selectedID}, {ID: configuredID}},
			"the configured policy with an empty entry list": {{ID: selectedID}, {ID: configuredID, Entries: []admissionstate.PolicyEntry{}}},
		} {
			if built, ok := operationalPolicySet(content); ok || built.policies != nil {
				t.Fatalf("%s: built=%+v ok=%t", name, built, ok)
			}
		}
		// Controls: the two shapes a Service can commission.
		for _, content := range [][]admissionstate.Policy{{{ID: selectedID}}, {{ID: selectedID}, {ID: configuredID, Entries: entry}}} {
			if built, ok := operationalPolicySet(content); !ok || len(built.policies) != len(content) {
				t.Fatalf("control: %+v built no set", content)
			}
		}
	})
	// No Service installs a view whose content builds no set:
	// operationalAdmissionContent maps the selected set, and the guard lists
	// the one call of Install. The admission state itself takes any content
	// that has a digest and a store token naming it, so the qualification
	// must refuse such a view, and must not evaluate an empty set in its
	// place. The views here are installed by hand with tokens of the store.
	t.Run("a view whose content builds no set answers Unavailable", func(t *testing.T) {
		ctx := context.Background()
		f := makeOperationalFixture(t, "")
		f.confirm()
		original := operationalV2Original(t, f)
		realm := f.domain.realm
		held := operationalInstalledView(f.service)
		byHand := func(t *testing.T, token reliablesubmit.OperationalAdmissionToken, content admissionstate.Content) *Service {
			t.Helper()
			return operationalServiceWithViewByHand(t, realm, token, content, nil)
		}
		// Control: the same construction with the commissioned content
		// qualifies the original, so a refusal below is about the policies.
		control := byHand(t, held.Token(), operationalViewContent(held))
		if reason := control.qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalReasonNone {
			t.Fatalf("control: a view installed by hand with the commissioned content: reason=%d", reason)
		}
		selectedID, configuredID := string(selectedDestructiveShellCommandPolicyID), string(configuredStaticScriptLiteralDenyPolicyID)
		entry := []admissionstate.PolicyEntry{{ID: "rule", Literal: "a literal the request does not contain"}}
		for _, tc := range []struct {
			name     string
			policies []admissionstate.Policy
		}{
			{"a policy this release does not know", []admissionstate.Policy{{ID: "execution-substrate.admission.unknown/v1"}}},
			{"the configured policy without the selected one", []admissionstate.Policy{{ID: configuredID, Entries: entry}}},
			{"a third policy", []admissionstate.Policy{{ID: selectedID}, {ID: configuredID, Entries: entry}, {ID: configuredID, Entries: entry}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				content := operationalViewContent(held)
				content.Policies = tc.policies
				digest, ok := admissionstate.Digest(content)
				if !ok {
					t.Fatal("control: the content has no digest, so no view could hold it")
				}
				token, err := f.domain.custody.AdvanceOperationalAdmission(ctx, realm.installation, realm.epoch, digest,
					operationalAdmissionRowAt(t, f).Generation)
				if err != nil {
					t.Fatalf("the store did not advance to the content: %v", err)
				}
				owner := byHand(t, token, content)
				if _, built := operationalPolicySet(operationalInstalledView(owner).Policies()); built {
					t.Fatal("control: the installed content builds a set")
				}
				if reason := owner.qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalUnavailable {
					t.Fatalf("reason=%d, want Unavailable", reason)
				}
			})
		}
	})
	// The test seam stricter is evaluated behind the built-in set of the view.
	// It can refuse what the set allows. It cannot allow what the set refuses:
	// a view whose configured policy denies the request answers Denied whether
	// or not a seam that allows everything is installed with it.
	t.Run("the stricter seam cannot allow what the built-in set refuses", func(t *testing.T) {
		ctx := context.Background()
		f := makeOperationalFixture(t, "")
		f.confirm()
		original := operationalV2Original(t, f)
		realm := f.domain.realm
		held := operationalInstalledView(f.service)
		// The literal is one the script of the fixture contains; the control
		// without a seam below shows that the set refuses it.
		content := operationalViewContent(held)
		content.Policies = []admissionstate.Policy{{ID: string(selectedDestructiveShellCommandPolicyID)},
			{ID: string(configuredStaticScriptLiteralDenyPolicyID), Entries: []admissionstate.PolicyEntry{{ID: "rule", Literal: "policy-fixture-ok"}}}}
		if _, built := operationalPolicySet(content.Policies); !built {
			t.Fatal("control: the content builds no set")
		}
		digest, ok := admissionstate.Digest(content)
		if !ok {
			t.Fatal("control: the content has no digest")
		}
		token, err := f.domain.custody.AdvanceOperationalAdmission(ctx, realm.installation, realm.epoch, digest,
			operationalAdmissionRowAt(t, f).Generation)
		if err != nil {
			t.Fatalf("the store did not advance to the content: %v", err)
		}
		evaluations := 0
		allowing := operationalRefusingFromPolicy{evaluations: &evaluations, from: 1 << 30}
		// Controls: the commissioned content with the allowing seam qualifies
		// the original and asks the seam, and with a refusing seam it does not
		// qualify.
		if reason := operationalServiceWithViewByHand(t, realm, held.Token(), operationalViewContent(held),
			&operationalAdmissionProofHooks{stricter: allowing}).qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalReasonNone || evaluations != 1 {
			t.Fatalf("control: an allowing seam behind a set that allows: reason=%d evaluations=%d", reason, evaluations)
		}
		refusals := 0
		if reason := operationalServiceWithViewByHand(t, realm, held.Token(), operationalViewContent(held),
			&operationalAdmissionProofHooks{stricter: operationalRefusingFromPolicy{evaluations: &refusals, from: 1}}).qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalDenied || refusals != 1 {
			t.Fatalf("control: a refusing seam behind a set that allows: reason=%d evaluations=%d", reason, refusals)
		}
		if reason := operationalServiceWithViewByHand(t, realm, token, content, nil).qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalDenied {
			t.Fatalf("control: the built-in set alone: reason=%d, want Denied", reason)
		}
		evaluations = 0
		if reason := operationalServiceWithViewByHand(t, realm, token, content,
			&operationalAdmissionProofHooks{stricter: allowing}).qualifyOperationalRetained(ctx, original, realm); reason != reliablesubmit.OperationalDenied {
			t.Fatalf("an allowing seam behind a set that refuses: reason=%d, want Denied", reason)
		}
		// The set stops at its first refusal, so the seam is not asked.
		if evaluations != 0 {
			t.Fatalf("the seam was asked %d times after the built-in set refused", evaluations)
		}
	})
	// The admission state copies the content it installs. The steps before
	// it copy too, so the set that is compared and the content that is named
	// by the digest cannot change under a writer to the Service's own values.
	// These copies are tested here on their own, because the copy at install
	// would hide the loss of any one of them.
	t.Run("each step before the install hands on a copy", func(t *testing.T) {
		source := []configuredStaticScriptLiteralDenyEntry{{id: "rule-1", literal: "rm -rf /"}}
		given := admissionPolicySet{policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{},
			configuredStaticScriptLiteralDenyPolicy{entries: source}}}
		copied, ok := copyOperationalPolicySet(given)
		if !ok {
			t.Fatal("control: the set was not copied")
		}
		source[0] = configuredStaticScriptLiteralDenyEntry{id: "written-after-the-copy", literal: "written-after-the-copy"}
		if got := copied.policies[1].(configuredStaticScriptLiteralDenyPolicy).entries; len(got) != 1 ||
			got[0] != (configuredStaticScriptLiteralDenyEntry{id: "rule-1", literal: "rm -rf /"}) {
			t.Fatalf("the copied set shares its entries with the set it was copied from: %+v", got)
		}

		f := makeOperationalFixture(t, "")
		service, _ := operationalUncommissionedService(t, f, nil)
		content, digest, ok := service.operationalAdmissionContent()
		if !ok || len(content.Verifier.PublicKey) == 0 || len(content.Trust.SignerPolicy.AllowedSigners) == 0 {
			t.Fatal("control: the Service has no content with a key and an allowed signer")
		}
		key := bytes.Clone(service.provenanceVerifier.publicKey)
		signers := append([]string(nil), service.trustModel.SignerPolicy.AllowedSigners...)
		content.Verifier.PublicKey[0] ^= 0xff
		content.Trust.SignerPolicy.AllowedSigners[0] = "written-after-the-copy"
		if !bytes.Equal(service.provenanceVerifier.publicKey, key) ||
			!reflect.DeepEqual(service.trustModel.SignerPolicy.AllowedSigners, signers) {
			t.Fatal("the content shares memory with the verifier or the trust model of the Service")
		}
		if again, sameDigest, ok := service.operationalAdmissionContent(); !ok || sameDigest != digest ||
			reflect.DeepEqual(again, content) {
			t.Fatal("a write to content that was handed out reached what the Service would enforce")
		}
	})
}
