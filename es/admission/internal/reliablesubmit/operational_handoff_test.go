package reliablesubmit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOperationalHandoffMigrationCompatibility(t *testing.T) {
	t.Run("IndependentScope3Wire", testOperationalOriginalWireVector)
	for _, fixture := range []struct {
		name    string
		version int
	}{
		{"bootstrap", 0},
		{"initial", 1},
		{"operation-replay", 2},
		{"original-custody", 3},
		{"fixture-progress", 4},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := context.Background()
			path := fixtureMigrationPath(t, fixture.name)
			beforeLegacy := fixtureSchemaVersion(t, path, fixture.version)
			store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
			if err != nil {
				t.Fatal(err)
			}
			var version, count int
			if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 5 {
				t.Fatalf("schema = %d, err = %v", version, err)
			}
			if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM reliable_submit_migrations").Scan(&count); err != nil || count != 5 {
				t.Fatalf("ledger rows = %d, err = %v", count, err)
			}
			if fixture.version > 0 && !reflect.DeepEqual(beforeLegacy, fixtureLegacyProjection(t, store.db, 5)) {
				t.Fatal("migration changed the carried legacy row")
			}
			if err := store.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.close(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("MixedLedgerRefuses", func(t *testing.T) {
		ctx := context.Background()
		path := fixtureMigrationPath(t, "mixed")
		fixtureSchemaVersion(t, path, 5)
		raw := openNonmigratingSQLiteFixture(t, path)
		if _, err := raw.db.Exec("DELETE FROM reliable_submit_migrations WHERE version=5"); err != nil {
			t.Fatal(err)
		}
		if err := raw.close(); err != nil {
			t.Fatal(err)
		}
		store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
		if store != nil || !errors.Is(err, errClaimStoreUnsupported) && !errors.Is(err, errClaimStoreCorrupt) {
			t.Fatalf("mixed schema opened: %v", err)
		}
	})
}

type operationalStoreFixture struct {
	t          *testing.T
	root, path string
	c          *OperationalCustody
	base       durableClaimRecord
	keys       PrivateReplayKeys
	token      OperationalAdmissionToken
}

// The store fixture's admission identity. The installation equals the one
// the fixture payload carries in its deployment leaf.
var (
	operationalStoreFixtureInstallation = [32]byte(bytes.Repeat([]byte{23}, 32))
	operationalStoreFixtureDigest       = [32]byte(bytes.Repeat([]byte{41}, 32))
)

const operationalStoreFixtureEpoch uint64 = 1

// newOperationalStoreFixture opens a provisioned domain and commissions its
// admission row at generation 1.
func newOperationalStoreFixture(t *testing.T, root string) *operationalStoreFixture {
	t.Helper()
	f := newUncommissionedOperationalStoreFixture(t, root)
	token, err := f.c.CommissionOperationalAdmission(context.Background(), operationalStoreFixtureInstallation,
		operationalStoreFixtureEpoch, operationalStoreFixtureDigest)
	if err != nil || !token.Valid() {
		t.Fatalf("commission fixture admission: %v", err)
	}
	f.token = token
	return f
}

func newUncommissionedOperationalStoreFixture(t *testing.T, root string) *operationalStoreFixture {
	t.Helper()
	ctx := context.Background()
	synthetic, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	keys := fixtureReplayKeys(t, 231)
	for _, k := range []struct {
		id string
		p  int
		fp [32]byte
	}{
		{keys.bindingID, 1, keys.bindingFP}, {keys.envelopeID, 2, keys.envelopeFP},
	} {
		if _, err := synthetic.store.db.Exec("INSERT INTO reliable_submit_key_registry VALUES (?,?,?,1)", k.id, k.p, k.fp[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := synthetic.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := OpenProvisionedOperationalCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	base, _ := syntheticReplayRecordFixture(t)
	return &operationalStoreFixture{t: t, root: root, path: filepath.Join(root, "reliable-submit.sqlite3"), c: c, base: base, keys: keys}
}

// This independent test vector uses the fixture's existing scalar/object
// construction, with operational deployment and scope leaves supplied anew.
func operationalFixturePayload(t *testing.T, base durableClaimRecord, keys PrivateReplayKeys, root string) []byte {
	t.Helper()
	f := progressVectorFields(t, fixtureReplayPayload(t, base, keys)[14:])
	realm := [][]byte{[]byte{0, 1}, bytes.Repeat([]byte{23}, 32), binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{24}, 32),
		bytes.Repeat([]byte{25}, 32), []byte("127.0.0.1"), []byte{0x11, 0x22}, []byte("global"), []byte("dc1"), []byte("es-operational-v1"),
		[]byte(root + "/stage"), []byte(root + "/results"), []byte(root + "/spire.sock"), bytes.Repeat([]byte{26}, 32), bytes.Repeat([]byte{27}, 32)}
	placement := progressVectorFields(t, f[6])
	placement[0], placement[1], placement[2], placement[3] = realm[10], realm[11], realm[12], realm[8]
	f[6] = progressVectorObject(placement...)
	digest := bytes.Repeat([]byte{28}, 32)
	f[5] = progressVectorObject([]byte("fixture@sha256:"+fmtHex(digest)), digest, []byte("owned-proof"), []byte{2}, realm[8])
	prov := progressVectorFields(t, f[7])
	prov[0], prov[4] = []byte("operational_local_v2"), []byte(`{"claims":{},"seal":{}}`)
	f[7] = progressVectorObject(prov...)
	formats := progressVectorFields(t, f[8])
	formats[3], formats[4] = []byte{0, 3}, []byte{0, 3}
	f[8] = progressVectorObject(formats...)
	f[9] = []byte{3}
	f = append(f, progressVectorObject(realm...))
	body := progressVectorObject(f...)
	header := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), 3)
	header = binary.BigEndian.AppendUint32(header, uint32(len(body)))
	return append(header, body...)
}

func TestOperationalHandoffV2CustodyStructure(t *testing.T) {
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	current := operationalFixturePayload(t, f.base, f.keys, f.root)
	if _, err := operationalOriginalView(context.Background(), current); err != nil {
		t.Fatalf("fixture v2 framing refused: %v", err)
	}
	build := func(variant string, record []byte) []byte {
		fields := progressVectorFields(t, current[14:])
		provenance := progressVectorFields(t, fields[7])
		provenance[0], provenance[4] = []byte(variant), record
		fields[7] = progressVectorObject(provenance...)
		body := progressVectorObject(fields...)
		header := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), 3)
		header = binary.BigEndian.AppendUint32(header, uint32(len(body)))
		return append(header, body...)
	}
	valid := build("operational_local_v2", []byte(`{"claims":{},"seal":{}}`))
	if _, err := operationalOriginalView(context.Background(), valid); err != nil {
		t.Fatalf("bounded opaque v2 leaf refused by custody: %v", err)
	}
	if _, err := freezeReplayOriginal(operationalReplayFormat, f.base.claim, f.base.plan, f.keys, valid); err != nil {
		t.Fatalf("v2 custody freeze refused: %v", err)
	}
	atCap := build("operational_local_v2", bytes.Repeat([]byte{'x'}, OperationalEvidenceLimit))
	if _, err := operationalOriginalView(context.Background(), atCap); err != nil {
		t.Fatalf("evidence at the shared cap refused by custody: %v", err)
	}
	// The published v1 layout: the v1 literal with an inherited provenance
	// sequence, empty or not. Scope-3 custody refuses the literal itself.
	publishedEmpty := binary.BigEndian.AppendUint16(nil, 0)
	legacyMember := progressVectorObject([]byte("synthetic"), []byte("record"), []byte("owner"))
	legacySequence := binary.BigEndian.AppendUint16(nil, 1)
	legacySequence = binary.BigEndian.AppendUint32(legacySequence, uint32(len(legacyMember)))
	legacySequence = append(legacySequence, legacyMember...)
	for name, raw := range map[string][]byte{
		"empty leaf":                      build("operational_local_v2", nil),
		"invalid UTF8":                    build("operational_local_v2", []byte{0xff}),
		"over cap":                        build("operational_local_v2", bytes.Repeat([]byte{'x'}, OperationalEvidenceLimit+1)),
		"unknown variant":                 build("operational_local_v3", []byte("{}")),
		"published v1 empty sequence":     build("operational_local_v1", publishedEmpty),
		"v1 nonempty sequence":            build("operational_local_v1", legacySequence),
		"v1 cannot carry opaque evidence": build("operational_local_v1", []byte("{}")),
		"v1 sequence member framing":      build("operational_local_v1", []byte{0, 1, 0, 0, 0, 8}),
		"fixture scope literal":           build("synthetic_progress_nonoperational_v1", []byte("{}")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := operationalOriginalView(context.Background(), raw); err == nil {
				t.Fatal("invalid scope-3 provenance reached authenticated use")
			}
			if _, err := freezeReplayOriginal(operationalReplayFormat, f.base.claim, f.base.plan, f.keys, raw); err == nil {
				t.Fatal("invalid scope-3 provenance could be frozen")
			}
		})
	}
}

func (f *operationalStoreFixture) establish(base durableClaimRecord) OperationalDisposition {
	f.t.Helper()
	raw := operationalFixturePayload(f.t, base, f.keys, f.root)
	return f.c.EstablishOperational(context.Background(), base.claim, base.plan, f.keys, raw, f.token).Disposition()
}

func (f *operationalStoreFixture) borrow(c *OperationalCustody, base durableClaimRecord, use func(*OperationalAccess, OperationalProjection)) OperationalDisposition {
	f.t.Helper()
	raw := operationalFixturePayload(f.t, base, f.keys, f.root)
	intent := progressVectorFields(f.t, raw[14:])[1]
	return c.WithOperationalOriginal(context.Background(), base.claim, f.keys, intent, OperationalRetainedRead,
		func(view *OperationalOriginalView) (OperationalOriginalMatch, error) {
			fields, err := view.Fields()
			if err != nil || len(fields) != 11 {
				f.t.Fatalf("borrowed original invalid: %v", err)
			}
			return MatchOperationalOriginal(base.claim, base.plan, raw)
		}, use).Disposition()
}

func operationalTestMutation(t *testing.T) OperationalMutation {
	t.Helper()
	m, err := NewOperationalMutation()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// testOperationalQualification models a process that holds whatever token
// the store currently has. Tests of the fence present an explicit token with
// testOperationalQualificationWith instead.
func testOperationalQualification(a *OperationalAccess) OperationalQualification {
	return func(current OperationalAdmissionToken) (OperationalOriginalMatch, error) {
		return OperationalOriginalMatch{claim: a.record.claim, plan: a.record.plan, digest: a.digest, admission: current}, nil
	}
}

func testOperationalQualificationWith(a *OperationalAccess, held OperationalAdmissionToken) OperationalQualification {
	return func(OperationalAdmissionToken) (OperationalOriginalMatch, error) {
		return OperationalOriginalMatch{claim: a.record.claim, plan: a.record.plan, digest: a.digest, admission: held}, nil
	}
}

func testOperationalStagePreimage(p OperationalProjection) []byte {
	// These descriptors are synthetic storage operands. The admission tests
	// prove real held descriptors before issuing any sender.
	buf := append([]byte("ESOHSTG1"), p.original[:]...)
	frame := func(data []byte) { buf = append(binary.BigEndian.AppendUint32(buf, uint32(len(data))), data...) }
	frame([]byte(p.run))
	buf = append(buf, p.intent[:]...)
	project := [32]byte{32}
	buf = append(buf, project[:]...)
	identity := func(tag byte, ino uint64, mode uint32) {
		buf = append(buf, tag)
		buf = binary.BigEndian.AppendUint64(buf, 17)
		buf = binary.BigEndian.AppendUint64(buf, ino)
		buf = binary.BigEndian.AppendUint32(buf, 501)
		buf = binary.BigEndian.AppendUint32(buf, 20)
		buf = binary.BigEndian.AppendUint32(buf, mode)
		buf = binary.BigEndian.AppendUint64(buf, 1)
	}
	identity(1, 22, 0o750)
	identity(1, 23, 0o750)
	buf = binary.BigEndian.AppendUint16(buf, 6)
	for i, entry := range []struct {
		name string
		tag  byte
		mode uint32
	}{
		{"payload", 1, 0o750}, {"payload/artifact.tar.gz", 2, 0o600},
		{"run", 1, 0o750}, {"run/platform", 1, 0o750}, {"run/platform/es-runtime-support", 2, 0o750}, {"run/result", 1, 0o750},
	} {
		frame([]byte(entry.name))
		identity(entry.tag, uint64(24+i), entry.mode)
		var digest [32]byte
		var length uint64
		if entry.tag == 2 {
			digest = sha256.Sum256([]byte{byte(i)})
			length = 1
		}
		buf = append(binary.BigEndian.AppendUint64(buf, length), digest[:]...)
	}
	return buf
}

func testOperationalMarker(t *testing.T, a *OperationalAccess, p OperationalProjection, m OperationalMutation) *OperationalMarkerCandidate {
	t.Helper()
	raw := testOperationalStagePreimage(p)
	proof := &OperationalStageProof{access: a, projection: p, preimage: raw, ref: sha256.Sum256(raw),
		locator: [32]byte{31}, project: [32]byte{32}, measure: func() ([]byte, error) { return bytes.Clone(raw), nil }}
	proof.self = proof
	marker, err := a.BindOperationalMarker(p, m, proof)
	if err != nil {
		t.Fatal(err)
	}
	return marker
}

func operationalStoreProgress(t *testing.T, a *OperationalAccess, p OperationalProjection) OperationalProjection {
	t.Helper()
	ctx := context.Background()
	qualify := testOperationalQualification(a)
	apply := func(cmd OperationalCommand) {
		status, next := a.Apply(ctx, p, operationalTestMutation(t), cmd, qualify)
		if status != OperationalApplied {
			t.Fatalf("progress from %d: %d", p.Revision(), status)
		}
		p = next
	}
	assign, err := NewAssignOperationalRun()
	if err != nil {
		t.Fatal(err)
	}
	apply(assign)
	intent, err := a.BindOperationalIntent(p, [32]byte{31})
	if err != nil {
		t.Fatal(err)
	}
	apply(intent)
	raw := testOperationalStagePreimage(p)
	stage, err := a.BindOperationalStage(p, [32]byte{32}, [32]byte{31}, raw, func() ([]byte, error) { return bytes.Clone(raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	apply(stage)
	return p
}

func TestOperationalHandoffWriterDisposition(t *testing.T) {
	t.Run("PrestageCleanupResults", testOperationalPrestageCleanupResults)
	for _, c := range []struct {
		name                string
		fault, rollback     bool
		want                OperationalDisposition
		callbacks, revision int
	}{
		{"DirectApplied", false, false, OperationalMarkerDirect, 1, 5},
		{"Rollback", true, true, OperationalDefinitelyNotApplied, 0, 4},
		{"CommitReplyLostAndConfirmed", true, false, OperationalOwnCommitConfirmed, 0, 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			if c.fault && f.c.ConfigureOperationalCommitFaultForProof(OperationalMark, c.rollback) != nil {
				t.Fatal("fault setup")
			}
			callbacks := 0
			out := f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
				p = operationalStoreProgress(t, a, p)
				mutation := operationalTestMutation(t)
				marker := testOperationalMarker(t, a, p, mutation)
				mint := func(OperationalProjection) { callbacks++ }
				admit := testOperationalQualification(a)
				status, _ := a.ApplyFirstMarker(context.Background(), p, mutation, marker, admit, mint)
				if status != c.want || callbacks != c.callbacks {
					t.Fatalf("disposition=%d callbacks=%d", status, callbacks)
				}
				if c.want == OperationalMarkerDirect {
					status, _ = a.ApplyFirstMarker(context.Background(), p, mutation, marker, admit, mint)
					if status != OperationalExactReplay || callbacks != 1 {
						t.Fatalf("exact marker replay=%d callbacks=%d", status, callbacks)
					}
				}
			})
			if out != OperationalCurrent {
				t.Fatalf("original lookup=%d", out)
			}
			f.borrow(f.c, f.base, func(_ *OperationalAccess, p OperationalProjection) {
				if p.Revision() != int64(c.revision) {
					t.Fatalf("retained revision %d", p.Revision())
				}
			})
		})
	}
}

func TestOperationalHandoffFirstMarkerCAS(t *testing.T) {
	for _, otherWins := range []bool{false, true} {
		t.Run(fmt.Sprintf("SecondHandleWins-%t", otherWins), func(t *testing.T) {
			ctx := context.Background()
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			other, err := OpenProvisionedOperationalCustody(ctx, f.root)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) { operationalStoreProgress(t, a, p) })
			chosen, loser := f.c, other
			if otherWins {
				chosen, loser = other, f.c
			}
			senders := 0
			if f.borrow(loser, f.base, func(a *OperationalAccess, stale OperationalProjection) {
				if stale.Revision() != 4 {
					t.Fatal("missing shared predecessor")
				}
				admit := testOperationalQualification(a)
				count := func(OperationalProjection) { senders++ }
				f.borrow(chosen, f.base, func(b *OperationalAccess, p OperationalProjection) {
					mutation := operationalTestMutation(t)
					marker := testOperationalMarker(t, b, p, mutation)
					k, _ := b.ApplyFirstMarker(ctx, p, mutation, marker, testOperationalQualification(b), count)
					if k != OperationalMarkerDirect {
						t.Fatalf("writer did not win: %d", k)
					}
				})
				mutation := operationalTestMutation(t)
				marker := testOperationalMarker(t, a, stale, mutation)
				k, _ := a.ApplyFirstMarker(ctx, stale, mutation, marker, admit, count)
				if k != OperationalStale || senders != 1 {
					t.Fatalf("second marker disposition=%d senders=%d", k, senders)
				}
			}) != OperationalCurrent {
				t.Fatal("first read failed")
			}
		})
	}
}

func TestOperationalHandoffKeyCutsAndCapacity(t *testing.T) {
	testOperationalReservationAndObjectBudget(t)
	t.Run("RetiredPairCannotGrantNewObject", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		if err := f.c.base.store.transitionReplayKeyState(context.Background(), f.keys.bindingID, replayKeyStateRetired); err != nil {
			t.Fatal(err)
		}
		if f.establish(f.base) != OperationalRefused {
			t.Fatal("retired key granted a new original")
		}
		entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("refusal created residue: %d %v", len(entries), err)
		}
	})
	t.Run("ExistingKeyAtFourSlotCapacity", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		if f.establish(f.base) != OperationalApplied {
			t.Fatal("initial claim")
		}
		for i := 1; i <= 4; i++ {
			boot := f.base
			boot.claim = mustPrivateClaimID(t, boot.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{byte(i + 181)}, 32)))
			expected := OperationalApplied
			if i == 4 {
				expected = OperationalRefused
			}
			if actual := f.establish(boot); actual != expected {
				t.Fatalf("capacity %d: %d", i, actual)
			}
		}
		if f.establish(f.base) != OperationalOccupied || f.borrow(f.c, f.base, func(_ *OperationalAccess, p OperationalProjection) {
			if p.Revision() != 1 {
				t.Fatal("occupied state changed")
			}
		}) != OperationalCurrent {
			t.Fatal("existing classification lost at capacity")
		}
	})
	t.Run("ScopeScopedRunCollision", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		if f.establish(f.base) != OperationalApplied {
			t.Fatal("first establish")
		}
		base := f.base
		base.claim = mustPrivateClaimID(t, base.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{173}, 32)))
		if f.establish(base) != OperationalApplied {
			t.Fatal("second establish")
		}
		cmd, err := NewAssignOperationalRun()
		if err != nil {
			t.Fatal(err)
		}
		for i, row := range []durableClaimRecord{f.base, base} {
			f.borrow(f.c, row, func(a *OperationalAccess, p OperationalProjection) {
				k, out := a.Apply(context.Background(), p, operationalTestMutation(t), cmd, testOperationalQualification(a))
				if i == 0 && k != OperationalApplied || i == 1 && (k == OperationalApplied || out.Revision() != 0) {
					t.Fatalf("same scoped run decision=%d on claim %d", k, i)
				}
			})
		}
		f.borrow(f.c, base, func(_ *OperationalAccess, p OperationalProjection) {
			if p.Revision() != 1 {
				t.Fatal("colliding row assigned")
			}
		})
	})
}

func TestOperationalHandoffSchema4BinaryRefusesSchema5(t *testing.T) {
	probe := os.Getenv("ES_REPLAY_SCHEMA4_PROBE")
	if probe == "" {
		t.Fatal("authenticated schema-4 opener is required")
	}
	root := fixtureReplayRoot(t)
	path := filepath.Join(root, "reliable-submit.sqlite3")
	legacy, _ := syntheticReplayRecordFixture(t)
	_, sealed, descriptor := unclaimedReplaySealedFixture(t, legacy, fixtureReplayKeys(t, 61))
	legacy, err := newReplayDurableClaimRecord(legacy.claim, legacy.plan, descriptor, legacy.createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, descriptor.ref), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	seedProgressMigrationV3WithOriginal(t, path, legacy)
	progress := legacy
	progress.claim = mustPrivateClaimID(t, legacy.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{64}, 32)))
	seedHistoricalSchema4Progress(t, root, path, progress, fixtureReplayKeys(t, 62))
	f := newOperationalStoreFixture(t, root)
	if f.establish(legacy) != OperationalOccupied || f.borrow(f.c, legacy, func(_ *OperationalAccess, _ OperationalProjection) {
		t.Fatal("legacy claim was projected through the operational original")
	}) != OperationalRefused {
		t.Fatal("legacy caller/key occupation was not preserved")
	}
	f.base.claim = mustPrivateClaimID(t, legacy.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{65}, 32)))
	if f.establish(f.base) != OperationalApplied {
		t.Fatal("populate operational original")
	}
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	before := replayLogicalWitness(t, path, 0)
	if before.version != 5 || before.digest != sqliteSchema5SHA256 || len(before.claims) != 5 || len(before.ledger) != 5 || len(before.keys) != 8 || len(before.grants) != 4 {
		t.Fatalf("incomplete target schema=%d claims=%d ledger=%d keys=%d grants=%d", before.version, len(before.claims), len(before.ledger), len(before.keys), len(before.grants))
	}
	snapshot := func() map[string][]byte {
		t.Helper()
		result := map[string][]byte{}
		dir := filepath.Join(root, "objects", "v1")
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 3 {
			t.Fatalf("sealed objects=%d error=%v", len(entries), err)
		}
		for _, d := range entries {
			b, err := os.ReadFile(filepath.Join(dir, d.Name()))
			if err != nil {
				t.Fatal(err)
			}
			result[d.Name()] = b
		}
		return result
	}
	objects := snapshot()
	physical := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			name := path + suffix
			info, err := os.Lstat(name)
			if os.IsNotExist(err) {
				out[suffix] = "absent"
				continue
			}
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("unqualified physical fixture for %q: %v", suffix, err)
			}
			payload, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			sys, ok := info.Sys().(*syscall.Stat_t)
			if !ok || sys.Nlink != 1 || sys.Uid != uint32(os.Getuid()) || sys.Gid != uint32(os.Getgid()) {
				t.Fatalf("unqualified owner or identity for %q", suffix)
			}
			out[suffix] = fmt.Sprintf("size=%d digest=%x mode=%o device=%d inode=%d links=%d", len(payload), sha256.Sum256(payload), info.Mode().Perm(), sys.Dev, sys.Ino, sys.Nlink)
		}
		return out
	}
	fileBefore := physical()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe, "-test.run=^TestPreviousSchema4OpenerProbe$", "-test.v")
	cmd.Env = append(os.Environ(), "ES_REPLAY_SCHEMA4_TARGET="+path)
	output, err := cmd.CombinedOutput()
	fileAfter := physical()
	t.Logf("quiescent old opener cuts main/WAL/SHM/journal: before=%v after=%v", fileBefore, fileAfter)
	if !reflect.DeepEqual(fileBefore, fileAfter) {
		t.Error("old opener changed quiescent physical state")
	}
	if err != nil || !strings.Contains(string(output), "SCHEMA4_REFUSED_SCHEMA5") ||
		!strings.Contains(string(output), "--- PASS: TestPreviousSchema4OpenerProbe") {
		t.Fatalf("old opener exit: %v: %s", err, output)
	}
	if !reflect.DeepEqual(before, replayLogicalWitness(t, path, 0)) || !reflect.DeepEqual(objects, snapshot()) {
		t.Fatal("old opener changed durable facts or sealed objects")
	}
	t.Log("SCHEMA4_REFUSED_SCHEMA5 with complete logical and sealed-object equality")
}

func TestOperationalHandoffHeldWriterExcludesPrestage(t *testing.T) {
	ctx := context.Background()
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	if f.establish(f.base) != OperationalApplied {
		t.Fatal("establish")
	}
	other, err := OpenProvisionedOperationalCustody(ctx, f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
		cmd, err := NewAssignOperationalRun()
		if err != nil {
			t.Fatal(err)
		}
		admit := testOperationalQualification(a)
		k, assigned := a.Apply(ctx, p, operationalTestMutation(t), cmd, admit)
		if k != OperationalApplied {
			t.Fatal("assign")
		}
		intent, err := a.BindOperationalIntent(assigned, [32]byte{80})
		if err != nil {
			t.Fatal(err)
		}
		k, prepared := a.Apply(ctx, assigned, operationalTestMutation(t), intent, admit)
		if k != OperationalApplied {
			t.Fatal("intent")
		}
		writer, err := other.base.store.checkedConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if _, err := writer.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		defer writer.ExecContext(ctx, "ROLLBACK")
		blocked, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
		defer cancel()
		stageAuthorizations := 0
		cut := func(current OperationalAdmissionToken) (OperationalOriginalMatch, error) {
			stageAuthorizations++
			return admit(current)
		}
		if k := a.Prestage(blocked, prepared, cut).Disposition(); k == OperationalNoChange || stageAuthorizations != 0 {
			t.Fatalf("unsettled writer admitted a stage: %d %d", k, stageAuthorizations)
		}
		if _, err := writer.ExecContext(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if k := a.Prestage(ctx, prepared, cut).Disposition(); k != OperationalNoChange || stageAuthorizations != 1 {
			t.Fatalf("settled writer did not admit stage: %d %d", k, stageAuthorizations)
		}
	}) != OperationalCurrent {
		t.Fatal("original was not authenticated")
	}
}

func testOperationalReservationAndObjectBudget(t *testing.T) {
	t.Run("PersistentSharedReservationLimit", func(t *testing.T) {
		ctx := context.Background()
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := fixtureReplayKeys(t, 151)
		for n := 0; n < 32; n++ {
			frozenDigest := [32]byte{byte(n + 1), 141}
			if _, err := f.c.base.store.reserveReplaySealUse(ctx, other, frozenDigest, false); err != nil {
				t.Fatalf("shared reservation %d: %v", n, err)
			}
		}
		if f.establish(f.base) != OperationalRefused {
			t.Fatal("operational reservation crossed the aggregate limit")
		}
		var count int
		if err := f.c.base.store.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&count); err != nil || count != 32 {
			t.Fatalf("ledger count=%d error=%v", count, err)
		}
		entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("ungranted original left residue: %v", err)
		}
	})
	t.Run("UnexpectedNameAndQualifiedOrphans", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			names   int
			pattern string
		}{
			{"UnexpectedName", 1, "unexpected-%d"},
			{"QualifiedOrphans", 32, "%064x"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
				dir := filepath.Join(f.root, "objects", "v1")
				for n := 1; n <= tc.names; n++ {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf(tc.pattern, n)), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if f.establish(f.base) != OperationalRefused {
					t.Fatal("invalid object accounting admitted new work")
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != tc.names {
					t.Fatalf("changed retained names count=%d error=%v", len(entries), err)
				}
				var charged int
				if err := f.c.base.store.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&charged); err != nil || charged != 1 {
					t.Fatalf("reservation was lost or refunded: %d, %v", charged, err)
				}
			})
		}
	})
	t.Run("IncompleteOrForeignKeyPair", func(t *testing.T) {
		for _, name := range []string{"Missing", "MismatchedFingerprint", "MixedPurpose", "Revoked"} {
			t.Run(name, func(t *testing.T) {
				f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
				var err error
				switch name {
				case "Missing":
					f.keys, err = NewPrivateReplayKeys("Unprovisioned-Binding", f.keys.binding[:], f.keys.envelopeID, f.keys.envelope[:])
				case "MismatchedFingerprint":
					f.keys, err = NewPrivateReplayKeys(f.keys.bindingID, bytes.Repeat([]byte{156}, 32), f.keys.envelopeID, f.keys.envelope[:])
				case "MixedPurpose":
					f.keys, err = NewPrivateReplayKeys(f.keys.envelopeID, f.keys.envelope[:], f.keys.bindingID, f.keys.binding[:])
				case "Revoked":
					err = f.c.base.store.transitionReplayKeyState(context.Background(), f.keys.envelopeID, replayKeyStateRevoked)
				}
				if err != nil {
					t.Fatal(err)
				}
				if f.establish(f.base) != OperationalRefused {
					t.Fatal("unqualified original key pair admitted new work")
				}
				var grants int
				if err := f.c.base.store.db.QueryRow("SELECT count(*) FROM reliable_submit_seal_use").Scan(&grants); err != nil || grants != 0 {
					t.Fatalf("unqualified pair changed the ledger: %d, %v", grants, err)
				}
			})
		}
	})
}

func testOperationalOriginalWireVector(t *testing.T) {
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	raw := operationalFixturePayload(t, f.base, f.keys, f.root)
	fields := progressVectorFields(t, raw[14:])
	frozen, err := freezeReplayOriginal(operationalReplayFormat, f.base.claim, f.base.plan, f.keys, raw)
	if err != nil {
		t.Fatal(err)
	}
	field := func(number uint16, value []byte) []byte {
		out := binary.BigEndian.AppendUint16(nil, number)
		out = append(out, 1)
		return append(binary.BigEndian.AppendUint32(out, uint32(len(value))), value...)
	}
	mac := func(domain string, items ...[]byte) []byte {
		actual := hmac.New(sha256.New, f.keys.binding[:])
		actual.Write([]byte(domain))
		for _, item := range items {
			actual.Write(item)
		}
		return actual.Sum(nil)
	}
	if !bytes.Equal(frozen.intentMAC[:], mac("ESRSINT3", field(2, fields[1]))) ||
		!bytes.Equal(frozen.contextMAC[:], mac("ESRSCTX3", field(6, fields[5]), field(7, fields[6]), field(8, fields[7]), field(11, fields[10]))) {
		t.Fatal("scope-3 commitments differ from the independent vector")
	}
	preimage := append([]byte("ESRSFRZ3"), f.keys.bindingFP[:]...)
	preimage = append(preimage, f.keys.envelopeFP[:]...)
	preimage = append(preimage, frozen.header...)
	if frozen.digest != sha256.Sum256(append(preimage, raw...)) {
		t.Fatal("scope-3 permit does not bind independent wire bytes")
	}
	if f.establish(f.base) != OperationalApplied {
		t.Fatal("did not seal the vector")
	}
	dir := filepath.Join(f.root, "objects", "v1")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("vector envelope count=%d error=%v", len(entries), err)
	}
	sealed, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || len(sealed) < 54 || string(sealed[:8]) != "ESRSENV3" ||
		binary.BigEndian.Uint16(sealed[8:10]) != 3 || binary.BigEndian.Uint16(sealed[14:16]) != 14 {
		t.Fatalf("vector wrapper shape or header: %v", err)
	}
	end := binary.BigEndian.Uint32(sealed[10:14])
	if end > 4096 || uint64(end)+28 >= uint64(len(sealed)) {
		t.Fatal("vector wrapper header length")
	}
	header := sealed[:end]
	block, err := aes.NewCipher(f.keys.envelope[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := gcm.Open(nil, sealed[end:end+12], sealed[end+12:], append([]byte("ESRSAAD3"), header...))
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("independent AES-GCM did not authenticate the exact vector")
	}
	for _, tc := range []struct {
		name  string
		alter func([]byte) []byte
	}{
		{"WrongScope", func(raw []byte) []byte { raw[9] = 2; return raw }},
		{"WrongMagic", func(raw []byte) []byte { raw[7] = '2'; return raw }},
		{"UnknownField", func(raw []byte) []byte { raw[17] = 12; return raw }},
		{"DuplicateField", func(raw []byte) []byte {
			next := 16 + 7 + len(fields[0])
			raw[next+1] = 1
			return raw
		}},
		{"OverflowLength", func(raw []byte) []byte { binary.BigEndian.PutUint32(raw[19:23], ^uint32(0)); return raw }},
		{"ExcessCount", func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[14:16], 65535); return raw }},
		{"TrailingByte", func(raw []byte) []byte { return append(raw, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := operationalOriginalView(context.Background(), tc.alter(bytes.Clone(raw))); err == nil {
				t.Fatal("invalid operational original parsed")
			}
		})
	}
	if _, _, err := progressReplayFormat.parseHeader(sealed); err == nil {
		t.Fatal("scope-2 wrapper accepted the scope-3 object")
	}
}

func TestOperationalHandoffOpeningCapacity(t *testing.T) {
	ctx := context.Background()
	for _, count := range []int{0, 3, 4, 5} {
		t.Run(fmt.Sprintf("OperationalRows%d", count), func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			fixtureKeys := fixtureReplayKeys(t, 57)
			legacy, _ := syntheticReplayRecordFixture(t)
			legacyFrozen, err := freezeReplayOriginal(syntheticReplayFormat, legacy.claim, legacy.plan, fixtureKeys, fixtureReplayPayload(t, legacy, fixtureKeys))
			if err != nil {
				t.Fatal(err)
			}
			permit, err := f.c.base.ReserveSealUse(ctx, legacyFrozen)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := f.c.base.PublishSealedSynthetic(ctx, legacyFrozen, permit)
			if err != nil {
				t.Fatal(err)
			}
			if _, established, err := f.c.base.EstablishSyntheticClaim(ctx, legacyFrozen, publication); err != nil || !established {
				t.Fatal("legacy seed", err)
			}
			for i := 0; i < count; i++ {
				base := f.base
				base.claim = mustPrivateClaimID(t, base.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{byte(190 + i)}, 32)))
				if i < 4 {
					if f.establish(base) != OperationalApplied {
						t.Fatal("normal slot refused", i)
					}
					continue
				}
				if f.establish(base) != OperationalRefused {
					t.Fatal("normal writer exceeded cap")
				}
				// Provision a fully authenticated additional row as test setup without using the operational slot gate.
				raw := operationalFixturePayload(t, base, f.keys, f.root)
				frozen, err := freezeReplayOriginal(operationalReplayFormat, base.claim, base.plan, f.keys, raw)
				if err != nil {
					t.Fatal(err)
				}
				grant, err := f.c.base.store.reserveReplaySealUse(ctx, f.keys, frozen.digest, false)
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := f.c.base.publishReplayOriginal(ctx, frozen, PrivateReplaySealPermit{permit: grant})
				if err != nil {
					t.Fatal(err)
				}
				mutation, err := randomOperationalMutation()
				if err != nil {
					t.Fatal(err)
				}
				r, err := newOperationalRecord(base.claim, base.plan, sealed.descriptor, time.Now(), mutation)
				if err != nil {
					t.Fatal(err)
				}
				args, err := sqliteRecordArgs(r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.c.base.store.db.Exec(sqliteInsertReplayClaimSQL, args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.c.Close(); err != nil {
				t.Fatal(err)
			}
			before := replayLogicalWitness(t, f.path, 0)
			c, err := OpenProvisionedOperationalCustody(ctx, f.root)
			if count == 5 {
				if c != nil || !errors.Is(err, errOperationalCapacity) {
					t.Fatalf("overfull store opened: %v", err)
				}
			} else if err != nil || c == nil {
				t.Fatalf("eligible store failed to open: %v", err)
			} else {
				f.c = c
				if count == 4 {
					base := f.base
					base.claim = mustPrivateClaimID(t, base.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{190}, 32)))
					if f.establish(base) != OperationalOccupied || f.borrow(c, base, func(_ *OperationalAccess, p OperationalProjection) {
						if p.Revision() != 1 {
							t.Fatal("existing claim changed")
						}
					}) != OperationalCurrent {
						t.Fatal("full store lost existing claim")
					}
					unoccupied := f.base
					unoccupied.claim = mustPrivateClaimID(t, f.base.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{199}, 32)))
					if status := f.establish(unoccupied); status != OperationalRefused {
						t.Fatalf("full-store new claim disposition: %d", status)
					}
				}
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, replayLogicalWitness(t, f.path, 0)) {
				t.Fatal("opening qualification changed durable state")
			}
		})
	}
}

func TestOperationalHandoffSchema5MalformedRefusal(t *testing.T) {
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	if f.establish(f.base) != OperationalApplied {
		t.Fatal("fixture establishment")
	}
	db := f.c.base.store.db
	snapshot := func() map[string][32]byte {
		t.Helper()
		original := filepath.Join(f.root, "objects", "v1")
		entries, err := os.ReadDir(original)
		if err != nil || len(entries) != 1 {
			t.Fatalf("fixture original: %v (count %d)", err, len(entries))
		}
		body, err := os.ReadFile(filepath.Join(original, entries[0].Name()))
		if err != nil {
			t.Fatal(err)
		}
		return map[string][32]byte{entries[0].Name(): sha256.Sum256(body)}
	}
	const from = " FROM reliable_submit_claims WHERE codec_version=5"
	const columns = "claim_rowid," + sqliteClaimColumns + "," + sqliteReplayColumns
	valid := func(revision claimRevision) durableClaimRecord {
		t.Helper()
		record, err := scanSQLiteClaim(db.QueryRow("SELECT " + columns + from))
		if err != nil || record.revision != revision || record.progressRowID <= 0 || !record.replay.validForScope(3) {
			t.Fatalf("unchanged fixture projection at revision %d: %v", revision, err)
		}
		return record
	}
	type invalidProjection struct{ name, field, expression string }
	refuses := func(t *testing.T, c invalidProjection) {
		t.Helper()
		fields := strings.Split(columns, ",")
		found := false
		for i, k := range fields {
			if strings.TrimSpace(k) == c.field {
				fields[i], found = c.expression, true
			}
		}
		if !found {
			t.Fatal("fixture column not present")
		}
		if c.expression == "x''" {
			var kind string
			var n, present int
			if err := db.QueryRow("SELECT typeof(x''),length(x''),x'' IS NOT NULL"+from).Scan(&kind, &n, &present); err != nil ||
				kind != "blob" || n != 0 || present != 1 {
				t.Fatalf("empty non-NULL BLOB control: %q %d %d %v", kind, n, present, err)
			}
		}
		record, err := scanSQLiteClaim(db.QueryRow("SELECT " + strings.Join(fields, ",") + from))
		if !errors.Is(err, errClaimStoreCorrupt) || record.progressRowID != 0 {
			t.Errorf("malformed row did not return corruption: %v", err)
		}
	}
	checkPhase := func(t *testing.T, revision claimRevision, cases []invalidProjection) {
		t.Helper()
		beforeRecord := valid(revision)
		before := replayLogicalWitness(t, f.path, 0)
		original := snapshot()
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { refuses(t, c) })
		}
		if !beforeRecord.equal(valid(revision)) || !reflect.DeepEqual(before, replayLogicalWitness(t, f.path, 0)) ||
			!reflect.DeepEqual(original, snapshot()) {
			t.Fatal("read-only projections changed row, rowid, schema, ledger or original")
		}
	}
	t.Run("Unassigned", func(t *testing.T) {
		checkPhase(t, 1, []invalidProjection{
			{"WrongCodec", "codec_version", "6"}, {"WrongScope", "replay_scope", "2"},
			{"NullCommitment", "intent_commitment", "NULL"}, {"OutOfOrderStage", "staging_ref", "randomblob(32)"},
			{"TextPhysicalRow", "claim_rowid", "CAST(claim_rowid AS TEXT)"}, {"EmptyRun", "run_ref", "x''"},
			{"EmptyReceipt", "receipt_ref", "x''"}, {"EmptyIntent", "effect_intent_ref", "x''"},
			{"EmptyStamp", "staging_ref", "x''"}, {"EmptyMarker", "dispatch_ref", "x''"},
			{"EmptyObservation", "provider_observation_ref", "x''"}, {"EmptyReconciliation", "reconciliation_ref", "x''"},
			{"SizedReconciliation", "reconciliation_ref", "randomblob(32)"},
		})
	})
	ctx := context.Background()
	if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
		p = operationalStoreProgress(t, a, p)
		run := valid(4).phase.run
		if !validOperationalRun(run) || len(run.ref.value) != 69 {
			t.Fatal("fixture did not retain a 69-byte run")
		}
		t.Run("Assigned", func(t *testing.T) {
			checkPhase(t, 4, []invalidProjection{
				{"FixtureWidthRun", "run_ref", "randomblob(32)"},
				{"BadPrefixRun", "run_ref", "CAST('oops-' || substr(CAST(run_ref AS TEXT),6) AS BLOB)"},
				{"UppercaseRun", "run_ref", "CAST('esoh-A' || substr(CAST(run_ref AS TEXT),7) AS BLOB)"},
				{"NonhexRun", "run_ref", "CAST('esoh-g' || substr(CAST(run_ref AS TEXT),7) AS BLOB)"},
				{"ZeroSuffixRun", "run_ref", "CAST('esoh-' || printf('%064d',0) AS BLOB)"},
				{"ShortIntent", "effect_intent_ref", "randomblob(31)"},
				{"LongStamp", "staging_ref", "randomblob(33)"},
				{"TextStamp", "staging_ref", "CAST(hex(staging_ref) AS TEXT)"},
			})
		})
		onApplied := func(OperationalProjection) {}
		admit := testOperationalQualification(a)
		mutation := operationalTestMutation(t)
		marker := testOperationalMarker(t, a, p, mutation)
		k, marked := a.ApplyFirstMarker(ctx, p, mutation, marker, admit, onApplied)
		if k != OperationalMarkerDirect {
			t.Fatalf("fixture marker: %d", k)
		}
		project, realm := [32]byte{32}, [32]byte{31}
		preimage := binary.BigEndian.AppendUint64(a.evidenceInput(marked, project, realm), 74)
		eval := [16]byte{75}
		preimage = append(preimage, eval[:]...)
		proof, err := a.BindVerifiedOperationalObservation(marked, project, realm, preimage, replayHMAC(a.keys.binding, "ESOHEVD1", preimage))
		if err != nil {
			t.Fatal(err)
		}
		k, p = a.Apply(ctx, marked, operationalTestMutation(t), proof, nil)
		if k != OperationalApplied || !p.Receipt().Valid() {
			t.Fatalf("fixture acceptance: %d", k)
		}
	}) != OperationalCurrent {
		t.Fatal("fixture original was not borrowed")
	}
	t.Run("Accepted", func(t *testing.T) {
		checkPhase(t, 6, []invalidProjection{
			{"ShortReceipt", "receipt_ref", "randomblob(31)"}, {"LongReceipt", "receipt_ref", "randomblob(33)"},
			{"ShortObservation", "provider_observation_ref", "randomblob(31)"},
			{"LongMarker", "dispatch_ref", "randomblob(33)"}, {"NullReceipt", "receipt_ref", "NULL"},
		})
	})
	t.Run("MissingScopedRunIndex", func(t *testing.T) {
		if _, err := db.Exec("DROP INDEX reliable_submit_operational_run_ref_unique"); err != nil {
			t.Fatal(err)
		}
		c, err := OpenProvisionedOperationalCustody(context.Background(), f.root)
		if c != nil || !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("noncanonical shape qualified: %v", err)
		}
	})
}

func TestOperationalHandoffIndependentReceiptVectors(t *testing.T) {
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	ctx := context.Background()
	if f.establish(f.base) != OperationalApplied {
		t.Fatal("establish")
	}
	var oldAccess *OperationalAccess
	var aged *OperationalPositiveProof
	if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
		oldAccess = a
		p = operationalStoreProgress(t, a, p)
		m := operationalTestMutation(t)
		marker := testOperationalMarker(t, a, p, m)
		project, locator := [32]byte{32}, [32]byte{31}
		var mutation [32]byte
		copy(mutation[:], m.value.ref.value)
		base := append(binary.BigEndian.AppendUint32(bytes.Clone(p.original[:]), uint32(len(p.run))), []byte(p.run)...)
		preimage := append([]byte("ESOHMRK1"), base...)
		for _, field := range [][32]byte{p.intent, p.stamp, project, locator, mutation} {
			preimage = append(preimage, field[:]...)
		}
		if sha256.Sum256(binary.BigEndian.AppendUint64(preimage, 4)) != marker.Ref() {
			t.Fatal("independent marker preimage differs")
		}
		copyOfMarker := *marker
		if k, _ := a.ApplyFirstMarker(ctx, p, m, &copyOfMarker, testOperationalQualification(a), func(OperationalProjection) {
			t.Fatal("copied marker issued callback")
		}); k != OperationalRefused {
			t.Fatal("copied marker accepted")
		}
		k, marked := a.ApplyFirstMarker(ctx, p, m, marker, testOperationalQualification(a), func(OperationalProjection) {})
		if k != OperationalMarkerDirect {
			t.Fatalf("marker %v", k)
		}
		for _, field := range [][32]byte{marked.stamp, marked.dispatch, project, locator} {
			base = append(base, field[:]...)
		}
		index := uint64(0x0102030405060708)
		evaluation := [16]byte{0x13, 0x26, 0x32, 0x45, 0x55, 0x66, 0x4a, 0x22, 0xb3, 0x3c, 0x94, 0x86, 0xa1, 0x6e, 0x41, 0xff}
		word := append(binary.BigEndian.AppendUint64(bytes.Clone(base), index), evaluation[:]...)
		mac := func(domain string, data []byte) [32]byte {
			h := hmac.New(sha256.New, f.keys.binding[:])
			_, _ = h.Write(append([]byte(domain), data...))
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			return sum
		}
		wantW := mac("ESOHEVD1", word)
		wantR := mac("ESOHREC1", append(bytes.Clone(base), wantW[:]...))
		for _, mutation := range []string{"zero", "original", "frame", "index", "uuid", "truncated"} {
			t.Run(mutation, func(t *testing.T) {
				wrong := bytes.Clone(word)
				witness := wantW
				switch mutation {
				case "zero":
					witness = [32]byte{}
				case "original":
					wrong[0] ^= 1
				case "frame":
					wrong[35] ^= 1
				case "index":
					clear(wrong[len(base) : len(base)+8])
				case "uuid":
					clear(wrong[len(base)+8:])
				case "truncated":
					wrong = wrong[:len(wrong)-1]
				}
				if mutation != "zero" {
					witness = mac("ESOHEVD1", wrong)
				}
				if proof, err := a.BindVerifiedOperationalObservation(marked, project, locator, wrong, witness); err == nil || proof != nil {
					t.Fatal("invalid witness acquired authority")
				}
			})
		}
		proof, err := a.BindVerifiedOperationalObservation(marked, project, locator, word, wantW)
		if err != nil || !bytes.Equal(proof.observation.ref.value, wantW[:]) || !bytes.Equal(proof.receipt.ref.value, wantR[:]) {
			t.Fatalf("valid vector refused: %v", err)
		}
		aged = proof
		copied := *proof
		if k, _ := a.Apply(ctx, marked, operationalTestMutation(t), &copied, nil); k != OperationalRefused {
			t.Fatal("copied acceptance proof admitted")
		}
		if f.borrow(f.c, f.base, func(other *OperationalAccess, otherProjection OperationalProjection) {
			if k, _ := other.Apply(ctx, otherProjection, operationalTestMutation(t), proof, nil); k != OperationalRefused {
				t.Fatal("foreign access accepted a proof")
			}
		}) != OperationalCurrent {
			t.Fatal("foreign access fixture failed")
		}
		k, accepted := a.Apply(ctx, marked, operationalTestMutation(t), proof, nil)
		if k != OperationalApplied || !a.VerifyOperationalReceipt(accepted, project, locator) {
			t.Fatalf("valid acceptance %v", k)
		}
	}) != OperationalCurrent {
		t.Fatal("fixture original was unavailable")
	}
	if k, _ := oldAccess.Apply(ctx, aged.projection, operationalTestMutation(t), aged, nil); k != OperationalRefused {
		t.Fatal("expired access accepted a proof")
	}
}

func testOperationalPrestageCleanupResults(t *testing.T) {
	for _, variant := range []string{"success", "modeled-release-response", "modeled-rollback-response", "caller-canceled"} {
		t.Run(variant, func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []string
			var observed OperationalCheck
			proof := OperationalPrestageProofHooks{
				AfterSemantic: func() { events = append(events, "semantic") },
				AfterRollback: func(ok bool) bool {
					if !ok {
						t.Fatal("real rollback did not succeed")
					}
					events = append(events, "rollback")
					return variant == "modeled-rollback-response"
				},
				AfterRelease: func(ok bool) bool {
					if !ok {
						t.Fatal("real connection release did not succeed")
					}
					events = append(events, "release")
					if variant == "caller-canceled" {
						cancel()
					}
					return variant == "modeled-release-response"
				},
				Observe: func(check OperationalCheck) { observed = check; events = append(events, "result") },
			}
			if err := f.c.ConfigureOperationalPrestageProofForProof(proof); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.c.ConfigureOperationalPrestageProofForProof(OperationalPrestageProofHooks{}) })
			var check OperationalCheck
			if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
				qualify := testOperationalQualification(a)
				assign, err := NewAssignOperationalRun()
				if err != nil {
					t.Fatal(err)
				}
				status, next := a.Apply(context.Background(), p, operationalTestMutation(t), assign, qualify)
				if status != OperationalApplied {
					t.Fatalf("assign=%v", status)
				}
				p = next
				intent, err := a.BindOperationalIntent(p, [32]byte{31})
				if err != nil {
					t.Fatal(err)
				}
				status, next = a.Apply(context.Background(), p, operationalTestMutation(t), intent, qualify)
				if status != OperationalApplied || next.Revision() != 3 {
					t.Fatalf("intent=%v revision=%d", status, next.Revision())
				}
				p = next
				check = a.Prestage(ctx, p, qualify)
			}) != OperationalCurrent {
				t.Fatal("original borrow")
			}
			wantEvents := []string{"semantic", "rollback", "release", "result"}
			if variant == "modeled-rollback-response" {
				wantEvents = []string{"semantic", "rollback", "result"}
			}
			if !reflect.DeepEqual(events, wantEvents) || check != observed || check.Disposition() != OperationalNoChange {
				t.Fatalf("events=%v check=%+v observed=%+v", events, check, observed)
			}
			want := OperationalReasonNone
			switch variant {
			case "modeled-release-response":
				want = OperationalClosed
			case "modeled-rollback-response":
				want = OperationalClosed
			case "caller-canceled":
				want = OperationalCanceled
			}
			if check.Reason() != want {
				t.Fatalf("reason=%v want=%v", check.Reason(), want)
			}
			var revision, stamp, marker, receipt int
			if err := f.c.base.store.db.QueryRow("SELECT revision, staging_ref IS NOT NULL, dispatch_ref IS NOT NULL, receipt_ref IS NOT NULL FROM reliable_submit_claims WHERE codec_version=5").Scan(&revision, &stamp, &marker, &receipt); err != nil {
				t.Fatal(err)
			}
			if revision != 3 || stamp != 0 || marker != 0 || receipt != 0 {
				t.Fatalf("state revision=%d stamp=%d marker=%d receipt=%d", revision, stamp, marker, receipt)
			}
		})
	}
	for _, variant := range []string{"KeyDenied", "StaleWinner"} {
		t.Run(variant, func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			var events []string
			if err := f.c.ConfigureOperationalPrestageProofForProof(OperationalPrestageProofHooks{
				AfterSemantic: func() { events = append(events, "semantic") },
				Observe:       func(OperationalCheck) { events = append(events, "result") },
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.c.ConfigureOperationalPrestageProofForProof(OperationalPrestageProofHooks{}) })
			var check OperationalCheck
			if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
				qualify := testOperationalQualification(a)
				assign, err := NewAssignOperationalRun()
				if err != nil {
					t.Fatal(err)
				}
				status, next := a.Apply(context.Background(), p, operationalTestMutation(t), assign, qualify)
				if status != OperationalApplied {
					t.Fatalf("assign=%v", status)
				}
				p = next
				intent, err := a.BindOperationalIntent(p, [32]byte{31})
				if err != nil {
					t.Fatal(err)
				}
				status, next = a.Apply(context.Background(), p, operationalTestMutation(t), intent, qualify)
				if status != OperationalApplied || next.Revision() != 3 {
					t.Fatalf("intent=%v revision=%d", status, next.Revision())
				}
				p = next
				if variant == "KeyDenied" {
					if _, err := f.c.base.store.db.Exec("UPDATE reliable_submit_key_registry SET state=3 WHERE purpose=1"); err != nil {
						t.Fatal(err)
					}
				} else {
					other, err := OpenProvisionedOperationalCustody(context.Background(), f.root)
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close()
					if f.borrow(other, f.base, func(b *OperationalAccess, winner OperationalProjection) {
						if winner.Revision() != 3 {
							t.Fatalf("winner predecessor=%d", winner.Revision())
						}
						raw := testOperationalStagePreimage(winner)
						stage, err := b.BindOperationalStage(winner, [32]byte{32}, [32]byte{31}, raw, func() ([]byte, error) { return bytes.Clone(raw), nil })
						if err != nil {
							t.Fatal(err)
						}
						status, advanced := b.Apply(context.Background(), winner, operationalTestMutation(t), stage, testOperationalQualification(b))
						if status != OperationalApplied || advanced.Revision() != 4 {
							t.Fatalf("winner stage=%v revision=%d", status, advanced.Revision())
						}
					}) != OperationalCurrent {
						t.Fatal("winner borrow")
					}
				}
				check = a.Prestage(context.Background(), p, qualify)
			}) != OperationalCurrent {
				t.Fatal("original borrow")
			}
			want := OperationalRefused
			if variant == "StaleWinner" {
				want = OperationalStale
			}
			if check.Disposition() != want || check.Reason() == OperationalReasonNone || !reflect.DeepEqual(events, []string{"result"}) {
				t.Fatalf("variant=%s check=%+v events=%v", variant, check, events)
			}
			var revision int
			if err := f.c.base.store.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&revision); err != nil {
				t.Fatal(err)
			}
			wantRevision := 3
			if variant == "StaleWinner" {
				wantRevision = 4
			}
			if revision != wantRevision {
				t.Fatalf("retained revision=%d want=%d", revision, wantRevision)
			}
		})
	}
}
