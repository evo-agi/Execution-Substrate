package admission

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"strings"

	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

func TestOperationalOriginalBindingAndCustody(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	caller, err := newSyntheticCallerFact(f.domain.caller.String())
	if err != nil {
		t.Fatal(err)
	}
	request, err := parsePrivateReplayDelivery(f.raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	resolved, failure := f.service.resolveExecutionForSubmit(ctx, request.request)
	if failure != nil {
		t.Fatalf("resolve selected fixture: %s", failure.Code)
	}
	if !validateOperationalPlan(request, resolved, f.domain.realm) {
		t.Fatalf("selected fixture: mode=%q profile=%q network=%t image=%t args=%d stage=%t result=%t identity=%t owner=%t",
			resolved.plan.mode, resolved.plan.runtimeProfile.name, resolved.plan.networkAccess, resolved.plan.runtimeProfile.image == f.service.cfg.Execution.BaseImage,
			len(resolved.plan.runtimeCommand.arguments), resolved.custodyPlacement.stagingRootDir == f.domain.realm.staging,
			resolved.custodyPlacement.resultsRootDir == f.domain.realm.results, resolved.host.spireSourceDir == filepath.Dir(f.domain.realm.spireSocket),
			resolved.host.owner == f.domain.realm.owner)
	}
	original, err := f.service.composeOperationalOriginal(ctx, request, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatalf("compose scope 3 original: %v", err)
	}
	if _, err := verifyOperationalOriginal(original.wire, f.domain.keys, f.domain.realm); err != nil {
		t.Fatalf("verify scope 3 original: %v", err)
	}
	if _, err := reliablesubmit.MatchOperationalOriginal(request.refs.claimID, original.assessment.boundPlan, original.wire); err != nil {
		t.Fatalf("store shape rejected scope 3 original: %v", err)
	}
	if got := f.domain.custody.EstablishOperational(ctx, request.refs.claimID, original.assessment.boundPlan, f.domain.keys.storage, original.wire).Disposition(); got != reliablesubmit.OperationalApplied {
		var cutoff int
		if err := f.db.QueryRow("SELECT count(*) FROM reliable_submit_seal_use").Scan(&cutoff); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
		t.Fatalf("scope 3 establishment refused: %d grants=%d objects=%d err=%v", got, cutoff, len(entries), err)
	}
}

func TestOperationalHandoffIndependentBindingVectors(t *testing.T) {
	for _, checkMutants := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained-fixture", true: "identity-controls"}[checkMutants], func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			frame := func(b []byte, value string) []byte {
				b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
				return append(b, []byte(value)...)
			}
			hmacRef := func(prefix string, value []byte) [32]byte {
				key := bytes.Repeat([]byte{181}, 32)
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write([]byte(prefix))
				_, _ = mac.Write(value)
				var ref [32]byte
				copy(ref[:], mac.Sum(nil))
				return ref
			}
			identity := func(buf []byte, name string) []byte {
				t.Helper()
				var st unix.Stat_t
				if err := unix.Lstat(name, &st); err != nil {
					t.Fatal(err)
				}
				tag := byte(2)
				if st.Mode&unix.S_IFMT == unix.S_IFDIR {
					tag = 1
				}
				buf = append(buf, tag)
				buf = binary.BigEndian.AppendUint64(buf, uint64(st.Dev))
				buf = binary.BigEndian.AppendUint64(buf, st.Ino)
				buf = binary.BigEndian.AppendUint32(buf, st.Uid)
				buf = binary.BigEndian.AppendUint32(buf, st.Gid)
				buf = binary.BigEndian.AppendUint32(buf, uint32(st.Mode)&0o7777)
				return binary.BigEndian.AppendUint64(buf, uint64(st.Nlink))
			}
			seen := false
			var evidence []byte
			f.domain.proof = &operationalHandoffProofHooks{beforeConsume: func(s *liveSender, owner *handoffOwner) {
				seen = true
				b := s.binding
				var request struct{ Job map[string]any }
				decoder := json.NewDecoder(bytes.NewReader(s.prepared))
				decoder.UseNumber()
				if err := decoder.Decode(&request); err != nil {
					t.Fatal(err)
				}
				meta := request.Job["Meta"].(map[string]any)
				correlation := meta["es_operational_correlation_v1"]
				delete(meta, "es_operational_correlation_v1")
				var canonicalJob bytes.Buffer
				encoder := json.NewEncoder(&canonicalJob)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(request.Job); err != nil {
					t.Fatal(err)
				}
				job := bytes.TrimSuffix(canonicalJob.Bytes(), []byte("\n"))
				r := f.domain.realm
				locator := append([]byte("ESOHLOC1"), r.installation[:]...)
				locator = binary.BigEndian.AppendUint64(locator, r.epoch)
				locator = append(locator, r.provider[:]...)
				locator = append(locator, r.spki[:]...)
				locator = frame(locator, r.host)
				locator = binary.BigEndian.AppendUint16(locator, r.port)
				for _, value := range []string{r.region, r.datacenter, "es-operational-v1", request.Job["ID"].(string)} {
					locator = frame(locator, value)
				}
				locator = append(locator, r.build[:]...)
				locator = append(locator, r.template[:]...)
				wantL := sha256.Sum256(locator)
				wantP := sha256.Sum256(frame(append([]byte("ESOHJOB1"), wantL[:]...), string(job)))
				prefix := frame(bytes.Clone(b.original[:]), b.run)
				wantI := sha256.Sum256(append(append([]byte("ESOHINT1"), prefix...), wantL[:]...))
				var actualIntent, mutation []byte
				if err := f.db.QueryRow("SELECT effect_intent_ref,last_mutation_ref FROM reliable_submit_claims WHERE revision=5").Scan(&actualIntent, &mutation); err != nil {
					t.Fatal(err)
				}
				stageRoot := filepath.Join(f.domain.stage.path, b.run)
				var children []string
				if err := filepath.WalkDir(stageRoot, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if path != stageRoot {
						children = append(children, strings.TrimPrefix(path, stageRoot+"/"))
					}
					return nil
				}); err != nil || (len(children) != 6 && len(children) != 8) {
					t.Fatalf("stage vector layout %v %v", children, err)
				}
				stage := append(append([]byte("ESOHSTG1"), prefix...), wantI[:]...)
				stage = append(stage, wantP[:]...)
				stage = identity(stage, f.domain.stage.path)
				stage = identity(stage, stageRoot)
				stage = binary.BigEndian.AppendUint16(stage, uint16(len(children)))
				for _, child := range children {
					path := filepath.Join(stageRoot, child)
					stage = identity(frame(stage, child), path)
					info, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					var digest [32]byte
					var size uint64
					if !info.IsDir() {
						data, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						digest, size = sha256.Sum256(data), uint64(len(data))
					}
					stage = append(binary.BigEndian.AppendUint64(stage, size), digest[:]...)
				}
				wantS := sha256.Sum256(stage)
				marker := append(append([]byte("ESOHMRK1"), prefix...), wantI[:]...)
				for _, value := range [][32]byte{wantS, wantP, wantL} {
					marker = append(marker, value[:]...)
				}
				wantD := sha256.Sum256(binary.BigEndian.AppendUint64(append(marker, mutation...), 4))
				evidence = bytes.Clone(prefix)
				for _, value := range [][32]byte{wantS, wantD, wantP, wantL} {
					evidence = append(evidence, value[:]...)
				}
				wantC := hmacRef("ESOHCOR1", evidence)
				if wantL != b.locator || wantP != b.project || !bytes.Equal(wantI[:], actualIntent) ||
					wantS != b.stamp || wantD != b.marker || correlation != hex.EncodeToString(wantC[:]) {
					t.Fatal("independent L/P/I/S/D/C preimages disagree with captured sender")
				}
				if checkMutants {
					modeAt := 8 + len(prefix) + 64 + 25
					changed := bytes.Clone(stage)
					changed[modeAt+3] ^= 0o20
					if sha256.Sum256(changed) == b.stamp {
						t.Fatal("changed mode produced the retained stage digest")
					}
					if hmacRef("ESOHCOR1", evidence[:len(evidence)-1]) == wantC {
						t.Fatal("truncated locator produced the retained carrier")
					}
				}
			}}
			out := f.submit()
			if !seen || out.kind != operationalAccepted {
				t.Fatalf("vector fixture did not reach acceptance: %v", out.kind)
			}
			evaluation, err := hex.DecodeString(strings.ReplaceAll(operationalTestEvaluation, "-", ""))
			if err != nil {
				t.Fatal(err)
			}
			input := append(binary.BigEndian.AppendUint64(bytes.Clone(evidence), operationalTestIndex), evaluation...)
			wantW := hmacRef("ESOHEVD1", input)
			wantR := hmacRef("ESOHREC1", append(evidence, wantW[:]...))
			var gotW, gotR []byte
			if err := f.db.QueryRow("SELECT provider_observation_ref,receipt_ref FROM reliable_submit_claims WHERE revision=6").Scan(&gotW, &gotR); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wantW[:], gotW) || !bytes.Equal(wantR[:], gotR) {
				t.Fatal("independent W/R witness preimages disagree with retained acceptance")
			}
		})
	}
}
