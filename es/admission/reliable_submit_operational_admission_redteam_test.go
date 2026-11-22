package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// Red-team regression tests for the PR #12 retained current-admission repair
// (PR #13). Every Service here is an explicitly commissioned local proof
// Service; there is still no production commissioning caller.
//
// Tests named TestRedTeamPR13Holds* attack the repair and pin the property
// that survived. TestRedTeamPR13GuardAccessInventoryEscapes pins a finding
// that held against the maintained typed access guard and fails until the
// guard (or its documented claim) is repaired.

func redTeamRevokeArtifact(t *testing.T, f *operationalFixture) func(*Service) {
	t.Helper()
	digest := operationalV2Original(t, f).resolved.plan.artifactDigest
	return func(s *Service) {
		s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts, digest)
	}
}

func redTeamUncommissionedService(f *operationalFixture) *Service {
	trust := snapshotRuntimeTrustModel(*f.service.trustModel)
	old := f.service.provenanceVerifier
	service := &Service{cfg: f.service.cfg, trustModel: &trust, trustModelVerified: true,
		provenanceVerifier: &ed25519Verifier{algorithm: old.algorithm, keyID: old.keyID,
			publicKey: bytes.Clone(old.publicKey)}}
	service.trustModelOwner = service
	return service
}

// redTeamRealmDomain opens the same custody and staging domain through a
// provider qualified for a changed realm identity.
func redTeamRealmDomain(t *testing.T, f *operationalFixture, change func(*operationalRealm)) *operationalDomain {
	t.Helper()
	realm := f.domain.realm
	change(&realm)
	certificate, err := x509.ParseCertificate(f.certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	address, err := netip.ParseAddr(realm.host)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newOperationalLoopbackProvider(realm, netip.AddrPortFrom(address, realm.port), roots, f.template)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := reliablesubmit.OpenProvisionedOperationalCustody(context.Background(), f.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	domain, err := newOperationalDomain(custody, provider, f.domain.keys, f.domain.caller)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = domain.close() })
	return domain
}

type redTeamSeed struct {
	name     string
	op       reliablesubmit.OperationalOperation
	rollback bool
	revision int
	stamped  bool
	marked   bool
	// completes reports whether a later allowing retry may still dispatch.
	completes bool
}

func redTeamSeeds() []redTeamSeed {
	return []redTeamSeed{
		{"assign rolled back", reliablesubmit.OperationalAssign, true, 1, false, false, true},
		{"assign committed reply lost", reliablesubmit.OperationalAssign, false, 2, false, false, true},
		{"intent rolled back", reliablesubmit.OperationalIntent, true, 2, false, false, true},
		{"intent committed reply lost", reliablesubmit.OperationalIntent, false, 3, false, false, true},
		{"stamp committed reply lost", reliablesubmit.OperationalStamp, false, 4, true, false, false},
		{"marker committed reply lost", reliablesubmit.OperationalMark, false, 5, true, true, false},
	}
}

func redTeamSeedFixture(t *testing.T, seed redTeamSeed) (*operationalFixture, operationalPrestageState) {
	t.Helper()
	f := makeOperationalFixture(t, "")
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(seed.op, seed.rollback); err != nil {
		t.Fatal(err)
	}
	first := f.submit()
	state := operationalPrestageStateAt(t, f)
	if first.kind == operationalAccepted || state.Revision != seed.revision || state.Stamp != seed.stamped ||
		state.Marker != seed.marked || state.Receipt || state.Posts != 0 {
		t.Fatalf("seed %q: result kind=%d op=%d write=%d reason=%d state=%+v", seed.name, first.kind, first.operation, first.write, first.reason, state)
	}
	return f, state
}

// redTeamEffects is the part of the durable and external state that a refused
// retry must never change. Provider GETs are read-only observation.
func redTeamEffects(s operationalPrestageState) [6]any {
	return [6]any{s.Revision, s.StageEntries, s.Stamp, s.Marker, s.Receipt, s.Posts}
}

// A retry after a crash at every writer, under every changed or missing
// current authority that the writer's own matrix does not cover, must not
// advance, stage, mark or POST. Where the claim had not staged, a later
// retry under the original allowing authority must still complete exactly
// once; a stamped or marked claim must never dispatch again.
func TestRedTeamPR13HoldsDenialMatrixAcrossCrashPoints(t *testing.T) {
	type change struct {
		name    string
		service func(*testing.T, *operationalFixture) *Service
	}
	changes := []change{
		{"no authority", func(*testing.T, *operationalFixture) *Service { return &Service{} }},
		{"never commissioned", func(_ *testing.T, f *operationalFixture) *Service { return redTeamUncommissionedService(f) }},
		{"commissioned then withdrawn", func(t *testing.T, f *operationalFixture) *Service {
			s := operationalProofService(t, f, nil)
			if !s.withdrawOperationalEffects() {
				t.Fatal("withdrawal unavailable")
			}
			return s
		}},
		{"signer removed from allowed list", func(t *testing.T, f *operationalFixture) *Service {
			return operationalProofService(t, f, func(s *Service) {
				s.trustModel.SignerPolicy.AllowedSigners = []string{"some-other-signer"}
			})
		}},
		{"empty allowed list", func(t *testing.T, f *operationalFixture) *Service {
			return operationalProofService(t, f, func(s *Service) { s.trustModel.SignerPolicy.AllowedSigners = nil })
		}},
		{"verifier key rotated under same key id", func(t *testing.T, f *operationalFixture) *Service {
			public, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			return operationalProofService(t, f, func(s *Service) {
				s.provenanceVerifier = &ed25519Verifier{algorithm: "ed25519", keyID: s.provenanceVerifier.keyID, publicKey: public}
			})
		}},
		{"verifier key id rotated", func(t *testing.T, f *operationalFixture) *Service {
			return operationalProofService(t, f, func(s *Service) {
				s.provenanceVerifier = &ed25519Verifier{algorithm: "ed25519", keyID: "rotated-provenance-key",
					publicKey: bytes.Clone(s.provenanceVerifier.publicKey)}
			})
		}},
		{"authority commissioned for another epoch", func(t *testing.T, f *operationalFixture) *Service {
			s := redTeamUncommissionedService(f)
			realm := f.domain.realm
			realm.epoch++
			if err := s.commissionOperationalAdmission(realm); err != nil {
				t.Fatal(err)
			}
			return s
		}},
		{"authority commissioned for another installation", func(t *testing.T, f *operationalFixture) *Service {
			s := redTeamUncommissionedService(f)
			realm := f.domain.realm
			realm.installation[0] ^= 0xff
			if err := s.commissionOperationalAdmission(realm); err != nil {
				t.Fatal(err)
			}
			return s
		}},
		{"artifact revoked", func(t *testing.T, f *operationalFixture) *Service {
			return operationalProofService(t, f, redTeamRevokeArtifact(t, f))
		}},
	}
	for _, seed := range redTeamSeeds() {
		t.Run(seed.name, func(t *testing.T) {
			f, seeded := redTeamSeedFixture(t, seed)
			for _, change := range changes {
				service := change.service(t, f)
				for _, entry := range []string{"handoff", "recover"} {
					var out operationalHandoffResult
					if entry == "handoff" {
						out = service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
					} else {
						out = service.recoverOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
					}
					after := operationalPrestageStateAt(t, f)
					if out.kind == operationalAccepted || out.receipt.Valid() || redTeamEffects(after) != redTeamEffects(seeded) {
						t.Fatalf("%s/%s gained an effect: kind=%d op=%d write=%d reason=%d before=%+v after=%+v",
							change.name, entry, out.kind, out.operation, out.write, out.reason, seeded, after)
					}
					// Before any stamp, the handoff entry must also withhold the run.
					if entry == "handoff" && !seed.stamped && (out.kind != operationalUnavailable || out.run != "") {
						t.Fatalf("%s/handoff disclosed an unstamped claim: kind=%d run=%q reason=%d", change.name, out.kind, out.run, out.reason)
					}
				}
			}
			final := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
			state := operationalPrestageStateAt(t, f)
			if seed.completes {
				if final.kind != operationalAccepted || final.run == "" || state.Revision != 6 || !state.Marker || state.Posts != 1 {
					t.Fatalf("allowing retry after refusals: kind=%d reason=%d state=%+v", final.kind, final.reason, state)
				}
				return
			}
			if final.kind == operationalAccepted || state.Posts != 0 || redTeamEffects(state) != redTeamEffects(seeded) {
				t.Fatalf("stamped or marked claim dispatched again: kind=%d reason=%d before=%+v after=%+v", final.kind, final.reason, seeded, state)
			}
		})
	}
}

// A withdrawn Service must not open a new claim for a fresh delivery: no
// claim row, no sealed original and no occupied submit key. The fixture
// Service is able to compose and submit that delivery (the control fixture,
// built the same way, is accepted), so the refusal comes only from the two
// authority samples around Establish. Removing both samples passed the whole
// es/admission suite at e544e0f. The second case withdraws between the two
// samples and so pins the later one on its own.
func TestRedTeamPR13HoldsNoNewClaimAfterWithdrawal(t *testing.T) {
	control := makeOperationalFixture(t, "")
	if out := control.submit(); out.kind != operationalAccepted || operationalPrestageStateAt(t, control).Claims != 1 {
		t.Fatalf("control fixture was not accepted: kind=%d reason=%d", out.kind, out.reason)
	}
	for _, when := range []string{"before the handoff", "between the two authority samples"} {
		t.Run(when, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			domain := f.reopen()
			withdrawn := false
			withdraw := func() { withdrawn = f.service.withdrawOperationalEffects() }
			if when == "before the handoff" {
				withdraw()
			} else {
				domain.proof = &operationalHandoffProofHooks{beforeEstablish: withdraw}
			}
			for _, recovery := range []bool{false, true} {
				out := f.service.operatePrivateHandoff(context.Background(), domain, f.domain.caller, f.raw, recovery)
				state := operationalPrestageStateAt(t, f)
				sealed, _ := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
				if !withdrawn || out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() ||
					state.Claims != 0 || state.StageEntries != 0 || state.Posts != 0 || len(sealed) != 0 {
					t.Fatalf("fresh delivery after withdrawal (recovery=%t, withdrawn=%t) opened a claim: kind=%d run=%q reason=%d sealed=%d state=%+v",
						recovery, withdrawn, out.kind, out.run, out.reason, len(sealed), state)
				}
				domain = f.reopen()
			}
		})
	}
}

// A realm commissioned for a later epoch, or for another installation, must
// not advance, disclose or read an original sealed for the earlier realm,
// with or without a matching Service authority. The earlier realm's own
// authority must be unaffected by those attempts.
func TestRedTeamPR13HoldsCrossRealmIsolation(t *testing.T) {
	for _, realm := range []struct {
		name   string
		change func(*operationalRealm)
	}{
		{"later epoch", func(r *operationalRealm) { r.epoch++ }},
		{"other installation", func(r *operationalRealm) { r.installation[31] ^= 0x01 }},
	} {
		for _, state := range []string{"intent", "accepted"} {
			t.Run(realm.name+"/"+state, func(t *testing.T) {
				var f *operationalFixture
				if state == "intent" {
					f = operationalSeedIntent(t)
				} else {
					f = makeOperationalFixture(t, "")
					if first := f.submit(); first.kind != operationalAccepted {
						t.Fatalf("accepted seed: kind=%d reason=%d", first.kind, first.reason)
					}
				}
				seeded := operationalPrestageStateAt(t, f)
				domain := redTeamRealmDomain(t, f, realm.change)
				matching := redTeamUncommissionedService(f)
				if err := matching.commissionOperationalAdmission(domain.realm); err != nil {
					t.Fatal(err)
				}
				for name, service := range map[string]*Service{"matching authority": matching, "original authority": f.service, "no authority": {}} {
					for _, out := range []operationalHandoffResult{
						service.handoffOperational(context.Background(), domain, domain.caller, f.raw),
						service.recoverOperational(context.Background(), domain, domain.caller, f.raw),
					} {
						after := operationalPrestageStateAt(t, f)
						if out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() ||
							redTeamEffects(after) != redTeamEffects(seeded) {
							t.Fatalf("%s crossed the realm boundary: kind=%d run=%q reason=%d before=%+v after=%+v",
								name, out.kind, out.run, out.reason, seeded, after)
						}
					}
				}
				final := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				if after := operationalPrestageStateAt(t, f); final.kind != operationalAccepted || after.Posts != 1 || after.Revision != 6 {
					t.Fatalf("original realm after cross-realm attempts: kind=%d reason=%d state=%+v", final.kind, final.reason, after)
				}
			})
		}
	}
}

// Reusing the retained submit key with a different invocation, or presenting
// the retained delivery as another caller, must not advance or disclose the
// retained claim under a denying or an allowing authority.
func TestRedTeamPR13HoldsSubmitKeyReuseAndCallerSubstitution(t *testing.T) {
	f := operationalSeedIntent(t)
	seeded := operationalPrestageStateAt(t, f)
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(f.raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var invocation map[string]any
	if err := json.Unmarshal(envelope["invocation"], &invocation); err != nil {
		t.Fatal(err)
	}
	invocation["argv"] = []string{"substituted"}
	changed, err := json.Marshal(invocation)
	if err != nil {
		t.Fatal(err)
	}
	envelope["invocation"] = changed
	reused, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	other, err := spiffeid.FromString("spiffe://synthetic.test/ns/other")
	if err != nil {
		t.Fatal(err)
	}
	denying := operationalProofService(t, f, redTeamRevokeArtifact(t, f))
	for name, service := range map[string]*Service{"denying": denying, "allowing": f.service} {
		for _, recovery := range []bool{false, true} {
			reuse := service.operatePrivateHandoff(context.Background(), f.reopen(), f.domain.caller, reused, recovery)
			if after := operationalPrestageStateAt(t, f); reuse.kind != operationalConflict || reuse.run != "" || reuse.receipt.Valid() ||
				redTeamEffects(after) != redTeamEffects(seeded) {
				t.Fatalf("%s key reuse (recovery=%t): kind=%d run=%q reason=%d state=%+v", name, recovery, reuse.kind, reuse.run, reuse.reason, after)
			}
			foreign := service.operatePrivateHandoff(context.Background(), f.reopen(), other, f.raw, recovery)
			if after := operationalPrestageStateAt(t, f); foreign.kind != operationalUnauthorized || foreign.run != "" ||
				redTeamEffects(after) != redTeamEffects(seeded) {
				t.Fatalf("%s caller substitution (recovery=%t): kind=%d run=%q state=%+v", name, recovery, foreign.kind, foreign.run, after)
			}
		}
	}
}

// Two Services share one custody and staging domain. One denies the retained
// artifact; the other allows it and is withdrawn concurrently at a varying
// cut. The denying Service must never perform a gated writer and the claim
// must never be POSTed more than once. Run with -race.
func TestRedTeamPR13HoldsConcurrentDenyingAuthorityNeverWrites(t *testing.T) {
	for iteration := 0; iteration < 14; iteration++ {
		f := operationalSeedIntent(t)
		denying := operationalProofService(t, f, redTeamRevokeArtifact(t, f))
		allowing := operationalProofService(t, f, nil)
		allowDomain, denyDomain := f.reopen(), f.reopen()
		var wait sync.WaitGroup
		var once sync.Once
		withdraw := func() {
			once.Do(func() {
				wait.Add(1)
				go func() {
					defer wait.Done()
					time.Sleep(time.Duration((iteration/7)*150) * time.Microsecond)
					allowing.withdrawOperationalEffects()
				}()
			})
		}
		allowDomain.proof = &operationalHandoffProofHooks{}
		switch iteration % 7 {
		case 0:
			allowDomain.proof.beforePrestage = withdraw
		case 1:
			allowDomain.proof.beforeStageCreate = withdraw
		case 2:
			allowDomain.proof.beforeMaterialize = withdraw
		case 3:
			allowDomain.proof.beforeStamp = withdraw
		case 4:
			allowDomain.proof.beforeMarker = withdraw
		case 5:
			allowDomain.proof.beforeConsume = func(*liveSender, *handoffOwner) { withdraw() }
		case 6:
			allowDomain.proof.beforeEntrySample = withdraw
		}
		var allowed, denied operationalHandoffResult
		wait.Add(2)
		go func() {
			defer wait.Done()
			allowed = allowing.handoffOperational(context.Background(), allowDomain, allowDomain.caller, f.raw)
		}()
		go func() {
			defer wait.Done()
			denied = denying.handoffOperational(context.Background(), denyDomain, denyDomain.caller, f.raw)
		}()
		wait.Wait()
		state := operationalPrestageStateAt(t, f)
		if state.Posts > 1 {
			t.Fatalf("iteration %d: more than one POST: %+v", iteration, state)
		}
		if denied.operation != 0 && denied.operation != reliablesubmit.OperationalAccept {
			t.Fatalf("iteration %d: denying Service performed gated writer %d (disposition %d): %+v", iteration, denied.operation, denied.write, state)
		}
		if allowed.kind == operationalAccepted && state.Posts != 1 {
			t.Fatalf("iteration %d: accepted without exactly one POST: %+v", iteration, state)
		}
	}
}

// A retry must not follow, adopt or write through a planted object at the
// assigned run's stage name, under a denying or an allowing authority.
func TestRedTeamPR13HoldsPlantedStageNameOnRetry(t *testing.T) {
	for _, plant := range []string{"symlink to directory", "dangling symlink", "directory with symlinked payload", "regular file"} {
		t.Run(plant, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
				t.Fatal(err)
			}
			first := f.submit()
			if first.run == "" {
				t.Fatalf("seed did not assign a run: kind=%d reason=%d", first.kind, first.reason)
			}
			outside := t.TempDir()
			name := filepath.Join(f.domain.realm.staging, first.run)
			var err error
			switch plant {
			case "symlink to directory":
				err = os.Symlink(outside, name)
			case "dangling symlink":
				err = os.Symlink(filepath.Join(outside, "absent"), name)
			case "directory with symlinked payload":
				if err = os.Mkdir(name, 0o700); err == nil {
					err = os.Symlink(outside, filepath.Join(name, "payload"))
				}
			case "regular file":
				err = os.WriteFile(name, nil, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			seeded := operationalPrestageStateAt(t, f)
			denying := operationalProofService(t, f, redTeamRevokeArtifact(t, f))
			for label, service := range map[string]*Service{"denying": denying, "allowing": f.service} {
				out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				after := operationalPrestageStateAt(t, f)
				entries, readErr := os.ReadDir(outside)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if out.kind == operationalAccepted || len(entries) != 0 || after.Posts != 0 || after.Stamp || after.Marker ||
					after.Revision != seeded.Revision {
					t.Fatalf("%s retry used a planted stage name: kind=%d reason=%d outside=%d state=%+v", label, out.kind, out.reason, len(entries), after)
				}
			}
		})
	}
}

// The sealed original, including its v2 evidence leaf, is authenticated by
// custody. Any in-place change to the retained object must refuse the retry
// under an allowing authority without advancing, staging or POSTing, and
// restoring the exact bytes must let the retry complete.
func TestRedTeamPR13HoldsSealedOriginalTamperRefused(t *testing.T) {
	f := operationalSeedIntent(t)
	seeded := operationalPrestageStateAt(t, f)
	objects := filepath.Join(f.root, "objects", "v1")
	entries, err := os.ReadDir(objects)
	if err != nil || len(entries) != 1 {
		t.Fatalf("sealed original inventory: %d %v", len(entries), err)
	}
	path := filepath.Join(objects, entries[0].Name())
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	overwrite := func(at int, value byte) {
		t.Helper()
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte{value}, int64(at)); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	random := rand.New(rand.NewSource(13))
	for i := 0; i < 48; i++ {
		at := random.Intn(len(sealed))
		if i < 16 {
			at = len(sealed) - 1 - random.Intn(len(sealed)/4) // bias toward the trailing provenance leaf
		}
		overwrite(at, sealed[at]^byte(1<<random.Intn(8)))
		out := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		after := operationalPrestageStateAt(t, f)
		overwrite(at, sealed[at])
		if out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() || redTeamEffects(after) != redTeamEffects(seeded) {
			t.Fatalf("tampered sealed original at %d/%d was used: kind=%d reason=%d before=%+v after=%+v", at, len(sealed), out.kind, out.reason, seeded, after)
		}
	}
	final := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
	if state := operationalPrestageStateAt(t, f); final.kind != operationalAccepted || state.Posts != 1 || state.Revision != 6 {
		t.Fatalf("restored sealed original did not complete: kind=%d reason=%d state=%+v", final.kind, final.reason, state)
	}
}

// Defense in depth below custody authentication: the retained qualifier is
// handed a changed evidence record directly. It may return a positive result
// only when the changed record carries the same signed claims (the evidence
// contract signs whitespace-normalized claims, and the seal is outside the
// signature); it must never qualify a record whose signed content differs or
// whose spelling is not the exact canonical encoding.
func TestRedTeamPR13HoldsChangedEvidenceNeverQualifies(t *testing.T) {
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)
	record := original.resolved.provenanceRecord
	if reason := f.service.qualifyOperationalRetained(context.Background(), original, f.domain.realm); reason != reliablesubmit.OperationalReasonNone {
		t.Fatalf("unchanged control did not qualify: reason=%d", reason)
	}
	var evidence evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(record), &evidence); err != nil {
		t.Fatal(err)
	}
	signed, err := evidence.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	qualifies := func(changed string) bool {
		forged := original
		forged.resolved.provenanceRecord = changed
		return f.service.qualifyOperationalRetained(context.Background(), forged, f.domain.realm) == reliablesubmit.OperationalReasonNone
	}
	refuse := func(label, changed string) {
		t.Helper()
		if changed == record {
			t.Fatalf("%s: mutation did not change the record", label)
		}
		if qualifies(changed) {
			t.Fatalf("%s: changed retained evidence qualified", label)
		}
	}
	random := rand.New(rand.NewSource(13))
	for i := 0; i < 6000; i++ {
		changed := []byte(record)
		switch random.Intn(4) {
		case 0:
			changed[random.Intn(len(changed))] ^= byte(1 << random.Intn(8))
		case 1:
			changed = changed[:random.Intn(len(changed))]
		case 2:
			at := random.Intn(len(changed) + 1)
			changed = append(changed[:at:at], append([]byte{byte(random.Intn(256))}, changed[at:]...)...)
		default:
			at := random.Intn(len(changed))
			changed = append(changed[:at:at], changed[at+1:]...)
		}
		if string(changed) == record || !qualifies(string(changed)) {
			continue
		}
		var accepted evidencev1.ArtifactEvidence
		if err := json.Unmarshal(changed, &accepted); err != nil {
			t.Fatalf("qualified record does not decode: %v", err)
		}
		canonical, err := accepted.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, signed) {
			t.Fatalf("mutation %d qualified with different signed claims: %q", i, changed)
		}
	}
	reencode := func(change func(*evidencev1.ArtifactEvidence)) string {
		changed := evidence
		change(&changed)
		encoded, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	// Signed-content changes.
	refuse("network access raised", reencode(func(e *evidencev1.ArtifactEvidence) { e.Claims.Admission.Execution.Access.NetworkAccess = true }))
	refuse("artifact type changed", reencode(func(e *evidencev1.ArtifactEvidence) { e.Claims.Package.Identity.ArtifactType = "container-image" }))
	refuse("capability added", reencode(func(e *evidencev1.ArtifactEvidence) {
		e.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"CAP_SYS_ADMIN"}
	}))
	refuse("environment key added", reencode(func(e *evidencev1.ArtifactEvidence) {
		runtime := &e.Claims.Admission.Execution.Runtime
		runtime.EnvironmentVariables = append(append([]string(nil), runtime.EnvironmentVariables...), "RED_TEAM_EXTRA")
	}))
	refuse("output id changed", reencode(func(e *evidencev1.ArtifactEvidence) { e.Claims.Admission.Authorization.Derivation.OutputID += "x" }))
	// A sibling artifact with the same payload, validly signed by the same
	// trusted signer and not itself revoked, must not stand in for the
	// retained artifact.
	verifier := f.service.operationalAdmission.verifier
	sibling := evidence
	identity, err := evidencev1.NewArtifactIdentity(evidence.Claims.Package.Identity.PayloadDigest,
		evidence.Claims.Package.Identity.ArtifactType, "sha256:"+strings.Repeat("5", 64))
	if err != nil {
		t.Fatal(err)
	}
	sibling.Claims.Package.Identity = identity
	siblingCanonical, err := sibling.Claims.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sibling.Seal = evidencev1.NewSeal(siblingCanonical, verifier.keyID, verifier.algorithm,
		base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(f.signerPrivateKey), siblingCanonical)))
	if err := evidencev1.Verify(sibling, verifier.keyID, verifier.algorithm, verifier.publicKey); err != nil ||
		sibling.Claims.Package.Identity.ArtifactDigest == evidence.Claims.Package.Identity.ArtifactDigest {
		t.Fatalf("sibling artifact precondition: %v", err)
	}
	siblingRecord, err := json.Marshal(sibling)
	if err != nil {
		t.Fatal(err)
	}
	refuse("validly signed sibling artifact", string(siblingRecord))
	// The seal key id is unsigned; a padded spelling passes the trimmed
	// signature check and must then fail exact trust-list membership.
	refuse("seal key id trailing space", reencode(func(e *evidencev1.ArtifactEvidence) { e.Seal.KeyID += " " }))
	refuse("seal key id leading space", reencode(func(e *evidencev1.ArtifactEvidence) { e.Seal.KeyID = " " + e.Seal.KeyID }))
	refuse("seal key id no-break space", reencode(func(e *evidencev1.ArtifactEvidence) { e.Seal.KeyID += "\u00a0" }))
	// Noncanonical spellings of the same record.
	refuse("leading whitespace", " "+record)
	refuse("trailing newline", record+"\n")
	refuse("trailing value", record+"{}")
	refuse("duplicate member", strings.Replace(record, "{", `{"claims":{},`, 1))
	refuse("unknown member", strings.Replace(record, "{", `{"extra":1,`, 1))
	refuse("member case", strings.Replace(record, `"claims"`, `"Claims"`, 1))
	refuse("empty", "")
	refuse("null", "null")
	refuse("oversize", record+strings.Repeat(" ", maxOperationalEvidenceBytes))
}

func FuzzRedTeamPR13DecodeOperationalEvidence(f *testing.F) {
	for _, seed := range []string{"", "{}", "null", `{"claims":{},"seal":{}}`, `{"claims":{"package":{"identity":{}}},"seal":{"key_id":"k"}}`, "[]", `"x"`, "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, record string) {
		evidence, err := decodeOperationalEvidence(record)
		if err != nil {
			return
		}
		encoded, marshalErr := json.Marshal(evidence)
		if marshalErr != nil || string(encoded) != record || len(record) > maxOperationalEvidenceBytes || evidence.Validate() != nil {
			t.Fatalf("accepted evidence is not the exact bounded valid canonical record: %q", record)
		}
	})
}

func FuzzRedTeamPR13ParsePrivateReplayDelivery(f *testing.F) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	f.Add([]byte(`{"schema_version":"` + reliableSubmitRequestSchemaV1 + `","reliable_submit":{"contract":"` + reliableSubmitContractV1 +
		`","submit_key":"MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE"},"invocation":{"schema_version":"v1","artifact_digest":"` + digest +
		`","derivation_spec_digest":"` + digest + `","output_id":"out","argv":["a"]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte{0xff, 0x00})
	caller, err := newSyntheticCallerFact("spiffe://synthetic.test/ns/admission")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		delivery, err := parsePrivateReplayDelivery(raw, caller)
		if err != nil {
			return
		}
		first, err := privateIncomingIntent(delivery)
		if err != nil {
			return
		}
		again, err := parsePrivateReplayDelivery(raw, caller)
		if err != nil {
			t.Fatal("accepted delivery did not parse a second time")
		}
		second, err := privateIncomingIntent(again)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatal("canonical incoming intent is not deterministic")
		}
	})
}

// FINDING (held): the maintained typed access guard accepts a same-site write
// to a protected field as long as the write does not spell the field as an
// assignment, keyed initializer, address or recognised chain. Each body below
// keeps the single inventoried read and adds one write. An exact allowed-read
// inventory must refuse every one of them; at PR #13 e544e0f it accepts all.
//
// This is the class of the earlier V2-G2 (parenthesized write counted as a
// read) and W1 (range, address and write-through counted as reads) findings.
// The test fails until the guard sees these shapes or the owner document
// names them as outside its claim and this table is narrowed to match.
func TestRedTeamPR13GuardAccessInventoryEscapes(t *testing.T) {
	const inner = "type inner struct{ n int }; "
	const flag = "type Service struct{ trustModelVerified bool; other int }; "
	for _, test := range []struct {
		name, declarations, fieldName, body string
	}{
		// Whole-value writes: no identifier occurrence of the field at all.
		{"whole-struct zero reset", flag, "trustModelVerified", "_ = s.trustModelVerified; *s = Service{}"},
		{"whole-struct positional set", flag, "trustModelVerified", "_ = s.trustModelVerified; *s = Service{true, 0}"},
		{"whole-struct keyed other member", flag, "trustModelVerified", "_ = s.trustModelVerified; *s = Service{other: 1}"},
		{"whole-struct copy from variable", flag, "trustModelVerified", "_ = s.trustModelVerified; var fresh Service; *s = fresh"},
		// Positional construction: the keyed form is an "initializer".
		{"positional literal construction", flag, "trustModelVerified", "_ = s.trustModelVerified; _ = &Service{true, 0}"},
		// A conversion in the chain rooted at the field is read as "read".
		{"conversion then pointer subfield assignment", inner + "type alias inner; type Service struct{ value *inner }; ", "value", "(*alias)(s.value).n = 1"},
		{"conversion then slice element assignment", "type ints []int; type Service struct{ value ints }; ", "value", "([]int)(s.value)[0] = 1"},
		{"conversion then builtin delete", "type table map[string]int; type Service struct{ value table }; ", "value", "delete(map[string]int(s.value), \"k\")"},
		{"conversion then builtin clear", "type ints []int; type Service struct{ value ints }; ", "value", "clear([]int(s.value))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+test.declarations+"func (s *Service) commission(){"+test.body+"}")
			field := requirePackageStructField(t, pkg, "Service", test.fieldName)
			allowedRead := map[string]int{"fixture.go:Service.commission|read": 1}
			if err := validateTypedFieldAccessInventory(test.name, pkg.referencesTo(field), allowedRead); err == nil {
				t.Fatalf("same-site protected write %q passed the exact allowed-read inventory", test.body)
			}
		})
	}
	// The authority construction inventory counts composite literals and
	// new(T) only. A zero-value declaration and a conversion from an
	// identically shaped struct are two more ways to make one. The second
	// one, applied to the installed snapshot in production code, passed the
	// build, go vet and the whole es/admission suite at e544e0f.
	for _, test := range []struct {
		name, alternate string
	}{
		{"zero-value authority construction", "func alternate() *operationalAdmissionSnapshot{var forged operationalAdmissionSnapshot; return &forged}"},
		{"same-shape conversion authority construction", "func alternate() *operationalAdmissionSnapshot{forged := operationalAdmissionSnapshot(struct{ owner int }{2}); return &forged}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const declarations = "package admission; type operationalAdmissionSnapshot struct{ owner int }; "
			const approved = "func commission() *operationalAdmissionSnapshot{return &operationalAdmissionSnapshot{owner:1}}; "
			want := map[string]string{"operationalAdmissionSnapshot": "fixture.go:commission"}
			mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+approved+test.alternate)
			if err := validateOperationalAuthorityConstruction(mutant, want); err == nil {
				t.Fatalf("alternate snapshot construction %q passed the exact construction inventory", test.alternate)
			}
		})
	}
}
