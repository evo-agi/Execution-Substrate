package admission

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"golang.org/x/sys/unix"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
)

type operationalFixture struct {
	t                *testing.T
	service          *Service
	egs              *operationalTrustAuthority
	domain           *operationalDomain
	receiver         *operationalReceiver
	raw              []byte
	db               *sql.DB
	root             string
	certificate      []byte
	template         []byte
	expectedEvidence string
	signerPrivateKey []byte
	required         atomic.Int32
	evaluated        atomic.Int32
}

func makeOperationalFixture(t *testing.T, mode string, argv ...string) *operationalFixture {
	t.Helper()
	ctx := context.Background()
	artifact := newPreparedArtifactFixture(t)
	artifact.evidence.Claims.Admission.Execution.Access.NetworkAccess = false
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &artifact, payload)
	evidenceBytes, err := json.Marshal(artifact.evidence)
	if err != nil {
		t.Fatal(err)
	}
	service, _, _ := newWorkstreamCTestService(t, artifact)
	fixture := &operationalFixture{t: t, service: service}
	service.operationalProof = &operationalAdmissionProofHooks{
		required:  func([]AdmissionPolicyInputClass) { fixture.required.Add(1) },
		evaluated: func(bool) { fixture.evaluated.Add(1) },
	}
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, artifact, payload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("operational handoff used the ordinary Submit transport")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	invocation := artifact.prepareRequest().Invocation
	invocation.Argv = append([]string(nil), argv...)
	raw, err := json.Marshal(map[string]any{
		"schema_version":  reliableSubmitRequestSchemaV1,
		"reliable_submit": map[string]any{"contract": reliableSubmitContractV1, "submit_key": key},
		"invocation":      invocation,
	})
	if err != nil {
		t.Fatal(err)
	}
	old, root := openPrivateReplayTestCustody(t)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "reliable-submit.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	binding, envelope := bytes.Repeat([]byte{181}, 32), bytes.Repeat([]byte{182}, 32)
	keys, err := newOperationalOriginalKeys("Operational-Binding", binding, "Operational-Envelope", envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id      string
		purpose int
		key     []byte
	}{
		{keys.bindingID, 1, binding}, {keys.envelopeID, 2, envelope},
	} {
		fp := sha256.Sum256(append([]byte("ESRSKEY1"), row.key...))
		if _, err := db.Exec("INSERT INTO reliable_submit_key_registry VALUES (?,?,?,1)", row.id, row.purpose, fp[:]); err != nil {
			t.Fatal(err)
		}
	}
	receiver, server, target, pin := newOperationalTestReceiver(t, mode)
	image := sha256.Sum256([]byte("owned operational proof image identity"))
	service.cfg.Execution.BaseImage = "fixture-runtime@sha256:" + hex.EncodeToString(image[:])
	template := operationalProofTemplate(t)
	realm := operationalRealm{
		installation: sha256.Sum256([]byte(t.Name() + "/installation")), provider: sha256.Sum256([]byte(t.Name() + "/provider")),
		spki: pin, build: sha256.Sum256([]byte("operational provider fixture source shape")),
		template: sha256.Sum256(operationalFrame([]byte("ESOHJTPL1"), template)),
		epoch:    1, host: "127.0.0.1", port: target.Port(), region: "global", datacenter: service.cfg.Nomad.Datacenter,
		staging: service.cfg.Execution.StagingRootDir, results: service.cfg.Execution.ResultsRootDir,
		spireSocket: service.cfg.Execution.SPIREWorkloadAPISocketPath, imageIssuer: "proof-image-issuer", image: image,
		owner: executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()},
	}
	// Proof setup: the synthetic fixture supplied and verified this trust model,
	// and a synthetic EGS serves the same model for the confirmation.
	service.trustModelVerified = true
	service.trustModelOwner = service
	fixture.egs = attachOperationalTrustAuthority(t, service, *service.trustModel)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	provider, err := newOperationalLoopbackProvider(realm, target, roots, template)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := reliablesubmit.OpenProvisionedOperationalCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	peer, err := spiffeid.FromString("spiffe://synthetic.test/ns/admission")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := newOperationalDomain(custody, provider, keys, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = domain.close() })
	if err := service.commissionOperationalAdmission(ctx, domain); err != nil {
		t.Fatalf("commission synthetic operational fixture: %v", err)
	}
	fixture.domain, fixture.receiver, fixture.raw, fixture.db = domain, receiver, raw, db
	fixture.root, fixture.certificate, fixture.template = root, server.Certificate().Raw, template
	fixture.expectedEvidence = string(evidenceBytes)
	fixture.signerPrivateKey = bytes.Clone(artifact.privateKey)
	return fixture
}

// operationalTrustAuthority is the synthetic EGS of one proof Service. It signs
// and serves one runtime trust model, which a test may replace, fail or
// observe. It grants nothing: the Service verifies the envelope and compares
// the served content with the content it was commissioned with.
type operationalTrustAuthority struct {
	t       *testing.T
	private ed25519.PrivateKey
	mu      sync.Mutex
	trust   egsmodel.RuntimeTrustPolicy
	fail    bool
	forge   bool
	fetches int
	onFetch func()
}

func attachOperationalTrustAuthority(t *testing.T, s *Service, trust egsmodel.RuntimeTrustPolicy) *operationalTrustAuthority {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &operationalTrustAuthority{t: t, private: private, trust: snapshotRuntimeTrustModel(trust)}
	s.trustModelVerifier = &ed25519Verifier{algorithm: "ed25519", keyID: "synthetic-egs", publicKey: public}
	s.egsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(a.handle))
	s.egsClient.client.Timeout = 5 * time.Second
	return a
}

func (a *operationalTrustAuthority) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.fetches++
	trust, fail, forge, hook := snapshotRuntimeTrustModel(a.trust), a.fail, a.forge, a.onFetch
	a.mu.Unlock()
	if hook != nil {
		hook()
	}
	if r.Method != http.MethodGet || r.URL.Path != "/v1/trust-model" {
		a.t.Errorf("synthetic EGS: unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	canonical, err := trust.CanonicalBytes()
	if err != nil {
		a.t.Errorf("synthetic EGS: canonical trust: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signer := a.private
	if forge {
		// A well-formed envelope under the right key id, signed by another key.
		if _, signer, err = ed25519.GenerateKey(nil); err != nil {
			a.t.Errorf("synthetic EGS: forging key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	body, err := json.Marshal(signedRuntimeTrustResponse{RuntimeTrust: trust, Algorithm: "ed25519", KeyID: "synthetic-egs",
		PayloadDigest: digestBytes(canonical), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer, canonical))})
	if err != nil {
		a.t.Errorf("synthetic EGS: encode: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serve replaces the trust model the synthetic EGS signs from now on.
func (a *operationalTrustAuthority) serve(trust egsmodel.RuntimeTrustPolicy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trust = snapshotRuntimeTrustModel(trust)
}

func (a *operationalTrustAuthority) failing(fail bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = fail
}

// forging makes the synthetic EGS sign with a key the Service does not hold.
func (a *operationalTrustAuthority) forging(forge bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forge = forge
}

func (a *operationalTrustAuthority) observe(hook func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onFetch = hook
}

func (a *operationalTrustAuthority) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fetches
}

// confirm records one confirmation with the synthetic EGS, as an
// effect-capable invocation does before its first authority sample.
func (f *operationalFixture) confirm() {
	f.t.Helper()
	f.service.confirmOperationalAdmission(context.Background())
	if _, ok := f.service.currentOperationalAdmission(f.domain.realm); !ok {
		f.t.Fatal("synthetic fixture confirmation did not yield a current view")
	}
}

func (f *operationalFixture) submit() operationalHandoffResult {
	return f.service.handoffOperational(context.Background(), f.domain, f.domain.caller, f.raw)
}

func (f *operationalFixture) reopen() *operationalDomain {
	f.t.Helper()
	c, err := reliablesubmit.OpenProvisionedOperationalCustody(context.Background(), f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	d, err := newOperationalDomain(c, f.domain.provider, f.domain.keys, f.domain.caller)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = d.close() })
	return d
}

func TestOperationalHandoffPrestageRecovery(t *testing.T) {
	t.Run("ChangedQualificationEpoch", testOperationalHandoffQualifiedEpochBlocksEffectsOnChangedPolicy)
	t.Run("FirstProcessWins", func(t *testing.T) { testOperationalTwoProcesses(t, 0) })
	t.Run("SecondProcessWins", func(t *testing.T) { testOperationalTwoProcesses(t, 1) })

	for _, tc := range []struct {
		name string
		op   reliablesubmit.OperationalOperation
	}{
		{"Establish", reliablesubmit.OperationalEstablish},
		{"Assign", reliablesubmit.OperationalAssign},
		{"Intent", reliablesubmit.OperationalIntent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(tc.op, false); err != nil {
				t.Fatal(err)
			}
			first := f.submit()
			posts, queries, _ := f.receiver.counts()
			entries, err := os.ReadDir(f.domain.realm.staging)
			if err != nil || len(entries) != 0 || posts != 0 || queries != 0 || first.write != reliablesubmit.OperationalOwnCommitConfirmed {
				t.Fatalf("uncertain pre-stage continued: kind=%d outcome=%d stage=%d posts=%d get=%d error=%v", first.kind, first.write, len(entries), posts, queries, err)
			}
			d := f.reopen()
			second := f.service.handoffOperational(context.Background(), d, d.caller, f.raw)
			if posts, _, _ = f.receiver.counts(); second.kind != operationalAccepted || posts != 1 || first.run != "" && first.run != second.run {
				t.Fatalf("later owner: result=%d original write=%d new write=%d posts=%d", second.kind, first.write, second.write, posts)
			}
		})
	}
}

func TestOperationalHandoffMarkerDispositionAndStageResidue(t *testing.T) {
	t.Run("KnownMarkerCanceledBeforeTransport", testOperationalHandoffKnownMarkerBeforeCanceledSend)
	testOperationalStageTamper(t)
	for _, tc := range []struct {
		name     string
		op       reliablesubmit.OperationalOperation
		rollback bool
		rev      int
	}{
		{"StampResponseLost", reliablesubmit.OperationalStamp, false, 4},
		{"MarkerRollback", reliablesubmit.OperationalMark, true, 4},
		{"MarkerResponseLost", reliablesubmit.OperationalMark, false, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(tc.op, tc.rollback); err != nil {
				t.Fatal(err)
			}
			first := f.submit()
			expected := reliablesubmit.OperationalOwnCommitConfirmed
			if tc.rollback {
				expected = reliablesubmit.OperationalDefinitelyNotApplied
			}
			if first.write != expected || first.run == "" {
				t.Fatalf("first run result=%d write=%d", first.kind, first.write)
			}
			probe := filepath.Join(f.domain.realm.staging, first.run, "payload", "artifact.tar.gz")
			held, err := os.ReadFile(probe)
			if err != nil || len(held) == 0 {
				t.Fatalf("physical residue missing: %v", err)
			}
			reopened := f.reopen()
			result := f.service.handoffOperational(context.Background(), reopened, reopened.caller, f.raw)
			newBytes, err := os.ReadFile(probe)
			var rev, grants int
			if err := f.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&rev); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&grants); err != nil {
				t.Fatal(err)
			}
			posts, _, _ := f.receiver.counts()
			if err != nil || !bytes.Equal(newBytes, held) || rev != tc.rev || grants != 1 || result.run != first.run || posts != 0 {
				t.Fatalf("later owner changed failed mutation or residue: phase=%d rev=%d grants=%d posts=%d", result.kind, rev, grants, posts)
			}
		})
	}
}

func TestOperationalHandoffStageParentRequalification(t *testing.T) {
	t.Run("ModeledOwnerDrift", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		d := f.domain.stage
		var held unix.Stat_t
		if err := unix.Fstat(d.fd, &held); err != nil {
			t.Fatal(err)
		}
		if !operationalStageParentIdentityMatches(custodyIdentityFromStat(held), d.identity, f.domain.realm.owner) {
			t.Fatal("held metadata control failed")
		}
		changedUID, changedGID := held, held
		changedUID.Uid++
		changedGID.Gid++
		for _, modeled := range []unix.Stat_t{changedUID, changedGID} {
			if operationalStageParentIdentityMatches(custodyIdentityFromStat(modeled), d.identity, f.domain.realm.owner) {
				t.Fatal("modeled owner drift passed the held identity predicate")
			}
		}
	})
	for _, cut := range []string{"before-stage", "before-stamp", "before-marker", "before-entry", "sibling-after-stamp"} {
		t.Run(cut, func(t *testing.T) {
			f := makeOperationalFixture(t, "positive")
			path := f.domain.stage.path
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chmod(path, info.Mode().Perm()); err != nil {
					t.Error(err)
				}
			}()
			changed := false
			drift := func() {
				if err := os.Chmod(path, info.Mode().Perm()|0o020); err != nil {
					t.Fatal(err)
				}
				changed = true
			}
			f.domain.proof = &operationalHandoffProofHooks{}
			switch cut {
			case "before-stage":
				f.domain.proof.beforePrestage = drift
			case "before-stamp":
				f.domain.proof.beforeStamp = drift
			case "before-marker":
				f.domain.proof.beforeMarker = drift
			case "before-entry":
				f.domain.proof.beforeConsume = func(*liveSender, *handoffOwner) { drift() }
			case "sibling-after-stamp":
				f.domain.proof.beforeConsume = func(*liveSender, *handoffOwner) {
					if err := os.Mkdir(filepath.Join(path, "fixture-sibling"), 0o750); err != nil {
						t.Fatal(err)
					}
					changed = true
				}
			}
			out := f.submit()
			posts, _, _ := f.receiver.counts()
			var revision int
			if err := f.db.QueryRow("SELECT revision FROM reliable_submit_claims").Scan(&revision); err != nil {
				t.Fatal(err)
			}
			wantRevision := map[string]int{"before-stage": 3, "before-stamp": 3, "before-marker": 4, "before-entry": 5, "sibling-after-stamp": 6}[cut]
			if !changed || revision != wantRevision || (posts == 1) != (cut == "sibling-after-stamp") || posts > 1 {
				t.Fatalf("stage boundary %s not witnessed: changed=%v revision=%d posts=%d outcome=%v", cut, changed, revision, posts, out.kind)
			}
			if cut == "before-stage" || cut == "before-stamp" || cut == "before-marker" {
				if out.run != "" || out.receipt.Valid() {
					t.Fatal("stage qualification failure disclosed a projection")
				}
			}
		})
	}

}

func TestOperationalHandoffTransportEntryCut(t *testing.T) {
	for _, cut := range []string{"direct", "close-before-entry", "cancel-at-sample", "cancel-after-entry"} {
		t.Run(cut, func(t *testing.T) {
			f := makeOperationalFixture(t, "inconclusive")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, getConn := operationalGetConnEventsOn(ctx)
			var postEntry, getEntry atomic.Int32
			f.domain.provider.exchangeEntry = func(method string) {
				if method == http.MethodPost {
					postEntry.Add(1)
					if cut == "cancel-after-entry" {
						cancel()
					}
				} else if method == http.MethodGet {
					getEntry.Add(1)
				}
			}
			defer func() { f.domain.provider.exchangeEntry = nil }()
			var escaped *liveSender
			var owner *handoffOwner
			f.domain.proof = &operationalHandoffProofHooks{
				beforeConsume: func(s *liveSender, o *handoffOwner) {
					escaped, owner = s, o
					if cut == "close-before-entry" {
						o.close()
					}
				},
				beforeEntrySample: func() {
					if cut == "cancel-at-sample" {
						cancel()
					}
				},
			}
			out := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
			posts, gets, redirects := f.receiver.counts()
			if out.write != reliablesubmit.OperationalMarkerDirect || escaped == nil || owner == nil || redirects != 0 {
				t.Fatalf("direct marker fixture failed: disposition=%v redirects=%d", out.write, redirects)
			}
			beforePost, beforeGet, beforeConn := postEntry.Load(), getEntry.Load(), getConn.Load()
			switch cut {
			case "direct":
				if posts != 1 || gets != 1 || beforePost != 1 || beforeGet != 1 || beforeConn != 2 {
					t.Fatalf("direct cut: POST entry=%d GET entry=%d GetConn=%d posts=%d gets=%d", beforePost, beforeGet, beforeConn, posts, gets)
				}
			case "cancel-after-entry":
				if beforePost != 1 || beforeGet != 0 || beforeConn != 0 || posts != 0 || gets != 0 {
					t.Fatalf("post-sample cancellation: POST entry=%d GET entry=%d GetConn=%d posts=%d gets=%d", beforePost, beforeGet, beforeConn, posts, gets)
				}
			default:
				if beforePost != 0 || beforeGet != 0 || beforeConn != 0 || posts != 0 || gets != 0 {
					t.Fatalf("refused cut: POST entry=%d GET entry=%d GetConn=%d posts=%d gets=%d", beforePost, beforeGet, beforeConn, posts, gets)
				}
			}
			_ = escaped.consume(owner)
			afterPosts, afterGets, afterRedirects := f.receiver.counts()
			if postEntry.Load() != beforePost || getEntry.Load() != beforeGet || getConn.Load() != beforeConn ||
				afterPosts != posts || afterGets != gets || afterRedirects != redirects {
				t.Fatal("escaped callback admitted another exchange entry or receiver ingress")
			}
		})
	}
	t.Run("CloseOrderedAfterEntry", func(t *testing.T) {
		f := makeOperationalFixture(t, "inconclusive")
		f.receiver.entered = make(chan struct{}, 1)
		f.receiver.release = make(chan struct{})
		var release sync.Once
		unblock := func() { release.Do(func() { close(f.receiver.release) }) }
		defer unblock()
		var postEntry, getEntry atomic.Int32
		f.domain.provider.exchangeEntry = func(method string) {
			if method == http.MethodPost {
				postEntry.Add(1)
			} else if method == http.MethodGet {
				getEntry.Add(1)
			}
		}
		defer func() { f.domain.provider.exchangeEntry = nil }()
		owner := make(chan *handoffOwner, 1)
		f.domain.proof = &operationalHandoffProofHooks{beforeConsume: func(_ *liveSender, o *handoffOwner) { owner <- o }}
		parent, getConn := operationalGetConnEvents()
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		completed := make(chan operationalHandoffResult, 1)
		go func() { completed <- f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw) }()
		select {
		case <-f.receiver.entered:
		case <-ctx.Done():
			t.Fatal("transport did not enter")
		}
		o := <-owner
		if o.mu.TryLock() {
			o.mu.Unlock()
			t.Fatal("synchronous entry released the owner lock")
		}
		closed := make(chan struct{})
		go func() { o.close(); close(closed) }()
		unblock()
		select {
		case <-closed:
		case <-ctx.Done():
			t.Fatal("close did not return after synchronous use")
		}
		select {
		case result := <-completed:
			posts, gets, redirects := f.receiver.counts()
			if result.write != reliablesubmit.OperationalMarkerDirect || posts != 1 || gets != 1 || redirects != 0 ||
				postEntry.Load() != 1 || getEntry.Load() != 1 || getConn.Load() != 2 {
				t.Fatalf("admitted entry: write=%v POST entry=%d GET entry=%d GetConn=%d posts=%d gets=%d", result.write, postEntry.Load(), getEntry.Load(), getConn.Load(), posts, gets)
			}
		case <-ctx.Done():
			t.Fatal("synchronous invocation did not return")
		}
	})
}

func TestOperationalHandoffSenderLifetime(t *testing.T) {
	for _, kind := range []string{"eligible", "wrong-digest", "wrong-binding", "closed-stage"} {
		t.Run(kind, func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			var postEntry atomic.Int32
			f.domain.provider.exchangeEntry = func(method string) {
				if method == http.MethodPost {
					postEntry.Add(1)
				}
			}
			defer func() { f.domain.provider.exchangeEntry = nil }()
			var escaped *liveSender
			var held *handoffOwner
			f.domain.proof = &operationalHandoffProofHooks{
				beforeConsume: func(s *liveSender, owner *handoffOwner) {
					escaped, held = s, owner
					copied := *s
					if rejected := (&liveSender{}).consume(owner); !rejected.refused {
						t.Fatal("zero sender")
					}
					if rejected := copied.consume(owner); !rejected.refused || !owner.open {
						t.Fatal("copied sender altered the original right")
					}
					foreign := &handoffOwner{domain: owner.domain, open: true}
					if rejected := s.consume(foreign); !rejected.refused || !owner.open {
						t.Fatal("foreign owner altered the original right")
					}
					switch kind {
					case "wrong-digest":
						s.prepared = append(s.prepared, ' ')
					case "wrong-binding":
						s.binding.marker[0] ^= 1
					case "closed-stage":
						if err := owner.stage.close(); err != nil {
							t.Fatal(err)
						}
					}
				},
			}
			out := f.submit()
			posts, _, _ := f.receiver.counts()
			if escaped == nil || held == nil || held.open || (posts == 1) != (kind == "eligible") || posts > 1 ||
				(out.kind == operationalAccepted) != (kind == "eligible") {
				t.Fatalf("sender lifetime: result=%v posts=%d", out.kind, posts)
			}
			wantEntry := int32(0)
			if kind == "eligible" {
				wantEntry = 1
			}
			if postEntry.Load() != wantEntry {
				t.Fatalf("POST method entry=%d want=%d", postEntry.Load(), wantEntry)
			}
			if rejected := escaped.consume(held); !rejected.refused || rejected.reason != reliablesubmit.OperationalClosed {
				t.Fatal("escaped sender remained live")
			}
			if postEntry.Load() != wantEntry {
				t.Fatal("escaped sender added POST method entry")
			}
		})
	}
}

func TestOperationalHandoffAuditResultMappings(t *testing.T) {
	t.Run("PrestageCleanup", testOperationalHandoffPrestageCleanup)
	t.Run("OccupiedSecondLookup", func(t *testing.T) {
		for _, secondWins := range []bool{false, true} {
			for _, variant := range []string{"changed", "equivalent", "unavailable", "foreign-scope"} {
				t.Run(fmt.Sprintf("%t-%s", secondWins, variant), func(t *testing.T) {
					f := makeOperationalFixture(t, "")
					winner, loser := f.domain, f.reopen()
					if secondWins {
						winner, loser = loser, winner
					}
					if err := winner.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
						t.Fatal(err)
					}
					winnerRaw, loserRaw := f.raw, f.raw
					if variant == "changed" {
						var wire map[string]json.RawMessage
						if err := json.Unmarshal(f.raw, &wire); err != nil {
							t.Fatal(err)
						}
						wire["mode"] = json.RawMessage(`"async"`)
						explicit, err := json.Marshal(wire)
						if err != nil {
							t.Fatal(err)
						}
						if secondWins {
							winnerRaw = explicit
						} else {
							loserRaw = explicit
						}
					}
					winningRun := ""
					loser.proof = &operationalHandoffProofHooks{beforeEstablish: func() {
						if variant == "foreign-scope" {
							ctx := context.Background()
							service, raw, caller, keys, image := privateReplayServiceFixture(t)
							catalog, err := newPrivateSyntheticKeyCatalog(keys)
							if err != nil {
								t.Fatal(err)
							}
							fixture, err := reliablesubmit.OpenPrivateReplayCustody(ctx, f.root)
							if err != nil {
								t.Fatal(err)
							}
							defer fixture.Close()
							if _, err := service.admitPrivateSyntheticReplay(ctx, fixture, raw, caller, catalog, image); err != nil {
								t.Fatalf("synthetic winner: %v", err)
							}
							return
						}
						first := f.service.handoffOperational(context.Background(), winner, winner.caller, winnerRaw)
						if first.operation != reliablesubmit.OperationalIntent || first.write != reliablesubmit.OperationalOwnCommitConfirmed || first.run == "" {
							t.Fatalf("winner did not retain its established row: %v %v", first.operation, first.write)
						}
						winningRun = first.run
						if variant == "unavailable" {
							f.hideOperationalOriginal()
						}
					}}
					result := f.service.handoffOperational(context.Background(), loser, loser.caller, loserRaw)
					want := map[string]operationalResultKind{"changed": operationalConflict, "equivalent": operationalPending,
						"unavailable": operationalUnavailable, "foreign-scope": operationalUnavailable}[variant]
					if variant != "equivalent" {
						winningRun = ""
					}
					var claims, grants int
					if err := f.db.QueryRow("SELECT count(*) FROM reliable_submit_claims").Scan(&claims); err != nil {
						t.Fatal(err)
					}
					if err := f.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&grants); err != nil {
						t.Fatal(err)
					}
					posts, _, _ := f.receiver.counts()
					if result.kind != want || result.write != reliablesubmit.OperationalOccupied || result.operation != reliablesubmit.OperationalEstablish ||
						result.run != winningRun || result.receipt.Valid() || claims != 1 || grants != 1 || posts != 0 ||
						variant == "foreign-scope" && result.reason != reliablesubmit.OperationalWrongScope {
						t.Fatalf("loser classification=%v disposition=%v claims=%d grants=%d posts=%d", result.kind, result.write, claims, grants, posts)
					}
				})
			}
		}
	})
	t.Run("PrestageCurrentCut", func(t *testing.T) {
		for _, variant := range []string{"active", "revoked", "stale"} {
			t.Run(variant, func(t *testing.T) {
				f := makeOperationalFixture(t, "")
				checked := false
				proof := &operationalHandoffProofHooks{beforePrestage: func() {
					checked = true
					switch variant {
					case "revoked":
						if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=3 WHERE purpose=1"); err != nil {
							t.Fatal(err)
						}
					case "stale":
						other := f.reopen()
						out := f.service.handoffOperational(context.Background(), other, other.caller, f.raw)
						if out.kind != operationalAccepted {
							t.Fatalf("independent current winner outcome %v", out.kind)
						}
					}
				}}
				f.domain.proof = proof
				out := f.submit()
				posts, _, _ := f.receiver.counts()
				if !checked {
					t.Fatal("did not reach the checked writer cut")
				}
				if variant == "active" {
					if out.kind != operationalAccepted || posts != 1 {
						t.Fatal("qualified control did not proceed")
					}
				} else {
					reason := reliablesubmit.OperationalIntegrity
					wantPosts := 0
					if variant == "stale" {
						reason, wantPosts = reliablesubmit.OperationalStaleReason, 1
					}
					if out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() || out.reason != reason ||
						out.operation != reliablesubmit.OperationalIntent || out.write != reliablesubmit.OperationalApplied || posts != wantPosts {
						t.Fatalf("prestage refusal: kind=%v reason=%v write=%v posts=%d", out.kind, out.reason, out.write, posts)
					}
				}
			})
		}
	})
	t.Run("EstablishmentConfirmation", func(t *testing.T) {
		for _, variant := range []string{"confirmed", "unavailable", "retired", "canceled", "direct"} {
			t.Run(variant, func(t *testing.T) {
				f := makeOperationalFixture(t, "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if variant == "direct" {
					f.domain.proof = &operationalHandoffProofHooks{afterEstablish: f.hideOperationalOriginal}
				} else {
					if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalEstablish, false, func() {
						switch variant {
						case "unavailable":
							f.hideOperationalOriginal()
						case "retired":
							if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=2"); err != nil {
								t.Fatal(err)
							}
						case "canceled":
							cancel()
						}
					}); err != nil {
						t.Fatal(err)
					}
				}
				out := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
				want := reliablesubmit.OperationalUnknown
				if variant == "confirmed" {
					want = reliablesubmit.OperationalOwnCommitConfirmed
				} else if variant == "direct" {
					want = reliablesubmit.OperationalAppliedReleaseFailed
				}
				f.assertOperationalCut(out, reliablesubmit.OperationalEstablish, want, 1, 0)
				if variant == "confirmed" || variant == "canceled" || variant == "retired" {
					read := f.service.recoverOperational(context.Background(), f.domain, f.domain.caller, f.raw)
					if read.kind != operationalPending || read.operation != 0 || read.run != "" || read.receipt.Valid() {
						t.Fatalf("separate recovery did not read the retained claim: %v", read.kind)
					}
				}
			})
		}
	})
	t.Run("UnresolvedIntentConfirmation", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		parent, entries := operationalGetConnEvents()
		ctx, cancel := context.WithCancel(parent)
		defer cancel()
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false, cancel); err != nil {
			t.Fatal(err)
		}
		out := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
		f.assertOperationalCut(out, reliablesubmit.OperationalIntent, reliablesubmit.OperationalUnknown, 3, 0)
		files, err := os.ReadDir(f.domain.stage.path)
		if err != nil || len(files) != 0 || entries.Load() != 0 {
			t.Fatalf("unresolved intent caused downstream work: stages=%d entries=%d: %v", len(files), entries.Load(), err)
		}
	})
	t.Run("ObservedStageCleanup", func(t *testing.T) {
		for _, existing := range []bool{false, true} {
			for _, cleanupError := range []bool{false, true} {
				for _, variant := range []string{"receipt", "unknown-stamp", "rolled-back-stamp"} {
					t.Run(fmt.Sprintf("%t-%t-%s", existing, cleanupError, variant), func(t *testing.T) {
						f := makeOperationalFixture(t, "")
						if existing {
							if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
								t.Fatal(err)
							}
							first := f.submit()
							if first.write != reliablesubmit.OperationalOwnCommitConfirmed || first.run == "" {
								t.Fatal("preexisting fixture progress failed")
							}
							f.domain = f.reopen()
						}
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						op, disposition, revision, posts := reliablesubmit.OperationalAccept, reliablesubmit.OperationalApplied, 6, 1
						switch variant {
						case "unknown-stamp":
							op, disposition, revision, posts = reliablesubmit.OperationalStamp, reliablesubmit.OperationalUnknown, 4, 0
							if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(op, false, cancel); err != nil {
								t.Fatal(err)
							}
						case "rolled-back-stamp":
							op, disposition, revision, posts = reliablesubmit.OperationalStamp, reliablesubmit.OperationalDefinitelyNotApplied, 3, 0
							if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(op, true); err != nil {
								t.Fatal(err)
							}
						}
						closeSeen := false
						f.domain.proof = &operationalHandoffProofHooks{afterStageClose: func(err error) error {
							if err != nil {
								t.Fatalf("real stage close failed: %v", err)
							}
							closeSeen = true
							if cleanupError {
								return errors.New("modeled stage close reply")
							}
							return nil
						}}
						out := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
						f.assertOperationalCut(out, op, disposition, revision, posts)
						if !closeSeen || cleanupError && (out.reason != reliablesubmit.OperationalClosed || out.run != "" || out.receipt.Valid()) ||
							!cleanupError && out.receipt.Valid() != (variant == "receipt") {
							t.Fatalf("cleanup result: close=%v reason=%v receipt=%v", closeSeen, out.reason, out.receipt.Valid())
						}
					})
				}
			}
		}
	})
}

func (f *operationalFixture) hideOperationalOriginal() {
	f.t.Helper()
	objects := filepath.Join(f.root, "objects", "v1")
	files, err := os.ReadDir(objects)
	if err != nil || len(files) != 1 {
		f.t.Fatalf("original fixture: %d %v", len(files), err)
	}
	original := filepath.Join(objects, files[0].Name())
	displaced := filepath.Join(f.t.TempDir(), "retained-original")
	if err := os.Rename(original, displaced); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		if err := os.Rename(displaced, original); err != nil {
			f.t.Error(err)
		}
	})
}

func (f *operationalFixture) assertOperationalCut(out operationalHandoffResult, op reliablesubmit.OperationalOperation,
	write reliablesubmit.OperationalDisposition, wantRevision, wantPosts int) {
	f.t.Helper()
	var revision int
	if err := f.db.QueryRow("SELECT revision FROM reliable_submit_claims").Scan(&revision); err != nil {
		f.t.Fatal(err)
	}
	posts, _, _ := f.receiver.counts()
	if out.operation != op || out.write != write || revision != wantRevision || posts != wantPosts ||
		(write == reliablesubmit.OperationalUnknown || write == reliablesubmit.OperationalAppliedReleaseFailed) && (out.run != "" || out.receipt.Valid()) {
		f.t.Fatalf("operation=%v disposition=%v revision=%d posts=%d projected=%v", out.operation, out.write, revision, posts, out.run != "")
	}
}

func TestOperationalHandoffReceiptRecovery(t *testing.T) {
	t.Run("ConcurrentReceiptWinner", testOperationalConcurrentReceipt)
	t.Run("LostReceiptResponseAndRetiredKeys", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalAccept, false); err != nil {
			t.Fatal(err)
		}
		first := f.submit()
		if first.kind != operationalAccepted || first.write != reliablesubmit.OperationalOwnCommitConfirmed {
			t.Fatalf("receipt outcome %d %d", first.kind, first.write)
		}
		if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=2"); err != nil {
			t.Fatal(err)
		}
		reopened := f.reopen()
		if err := reopened.stage.close(); err != nil {
			t.Fatal(err)
		}
		posts, gets, _ := f.receiver.counts()
		recovered := (&Service{}).recoverOperational(context.Background(), reopened, reopened.caller, f.raw)
		afterPosts, afterGets, _ := f.receiver.counts()
		if recovered.kind != operationalAccepted || recovered.run != first.run || !recovered.receipt.Equal(first.receipt) ||
			afterPosts != posts || afterGets != gets || posts != 1 {
			t.Fatalf("receipt replay changed run, evidence or effects: %d", recovered.kind)
		}
		if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=3 WHERE purpose=1"); err != nil {
			t.Fatal(err)
		}
		refused := (&Service{}).recoverOperational(context.Background(), reopened, reopened.caller, f.raw)
		if refused.kind != operationalUnavailable || refused.run != "" || refused.receipt.Valid() {
			t.Fatal("revoked original disclosed receipt")
		}
	})
	t.Run("AuthorizationPrecedesLookup", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		f.domain.custody = nil
		peer := spiffeid.RequireFromString("spiffe://synthetic.test/other")
		out := f.service.handoffOperational(context.Background(), f.domain, peer, f.raw)
		if out.kind != operationalUnauthorized || out.run != "" || out.receipt.Valid() {
			t.Fatal("unauthorized projection")
		}
	})
}

type operationalChildFixture struct {
	Root, Caller, Target, Host, Region, Datacenter, Stage, Results, Socket, ImageIssuer string
	Installation, Provider, SPKI, Build, TemplateDigest, Image                          [32]byte
	Epoch                                                                               uint64
	Port                                                                                uint16
	UID, GID                                                                            int
	Certificate, Template, Request                                                      []byte
	Trust                                                                               egsmodel.RuntimeTrustPolicy
	VerifierKeyID, VerifierAlgorithm                                                    string
	VerifierKey                                                                         []byte
	// HoldBeforePrestage makes the child report that it is held between two
	// writer turns and wait for a second "go"; it then reports its result
	// without asserting one.
	HoldBeforePrestage bool
}

func (f *operationalFixture) childFixture() operationalChildFixture {
	realm := f.domain.realm
	return operationalChildFixture{
		Root: f.root, Caller: f.domain.caller.String(), Target: f.domain.provider.target.String(), Host: realm.host,
		Region: realm.region, Datacenter: realm.datacenter, Stage: realm.staging, Results: realm.results, Socket: realm.spireSocket, ImageIssuer: realm.imageIssuer,
		Installation: realm.installation, Provider: realm.provider, SPKI: realm.spki, Build: realm.build, TemplateDigest: realm.template, Image: realm.image,
		Epoch: realm.epoch, Port: realm.port, UID: realm.owner.UID, GID: realm.owner.GID, Certificate: f.certificate, Template: f.template, Request: f.raw,
		Trust: *f.service.trustModel, VerifierKeyID: f.service.provenanceVerifier.keyID,
		VerifierAlgorithm: f.service.provenanceVerifier.algorithm, VerifierKey: f.service.provenanceVerifier.publicKey,
	}
}

func TestOperationalHandoffChildProcess(t *testing.T) {
	path := os.Getenv("ES_OPERATIONAL_CHILD_FIXTURE")
	if path == "" {
		t.Skip("operational child sentinel, executed by TestOperationalHandoffPrestageRecovery")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f operationalChildFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	c, err := reliablesubmit.OpenProvisionedOperationalCustody(context.Background(), f.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	realm := operationalRealm{
		installation: f.Installation, provider: f.Provider, spki: f.SPKI, build: f.Build, template: f.TemplateDigest, epoch: f.Epoch,
		host: f.Host, region: f.Region, datacenter: f.Datacenter, port: f.Port,
		staging: f.Stage, results: f.Results, spireSocket: f.Socket, imageIssuer: f.ImageIssuer, image: f.Image,
		owner: executionPlatformStateOwner{UID: f.UID, GID: f.GID},
	}
	cert, err := x509.ParseCertificate(f.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	p, err := newOperationalLoopbackProvider(realm, netip.MustParseAddrPort(f.Target), roots, f.Template)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := newOperationalOriginalKeys("Operational-Binding", bytes.Repeat([]byte{181}, 32), "Operational-Envelope", bytes.Repeat([]byte{182}, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := spiffeid.RequireFromString(f.Caller)
	d, err := newOperationalDomain(c, p, keys, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	fmt.Println("ES_OPERATIONAL_CHILD_READY")
	var gate string
	if _, err := fmt.Fscanln(os.Stdin, &gate); err != nil || gate != "go" {
		t.Fatalf("missing process barrier: %v", err)
	}
	service := &Service{trustModel: &f.Trust, provenanceVerifier: &ed25519Verifier{
		algorithm: f.VerifierAlgorithm, keyID: f.VerifierKeyID, publicKey: f.VerifierKey}, trustModelVerified: true}
	service.trustModelOwner = service
	attachOperationalTrustAuthority(t, service, f.Trust)
	if err := service.commissionOperationalAdmission(context.Background(), d); err != nil {
		t.Fatalf("commission child proof service: %v", err)
	}
	if f.HoldBeforePrestage {
		d.proof = &operationalHandoffProofHooks{beforePrestage: func() {
			fmt.Println("ES_OPERATIONAL_CHILD_HELD")
			if _, err := fmt.Fscanln(os.Stdin, &gate); err != nil || gate != "go" {
				t.Errorf("missing second process barrier: %v", err)
			}
		}}
		result := service.handoffOperational(context.Background(), d, peer, f.Request)
		fmt.Printf("ES_OPERATIONAL_CHILD_HELD_RESULT %d %d %d %d %t %t\n", result.kind, result.reason, result.operation, result.write,
			result.run != "", result.receipt.Valid())
		return
	}
	result := service.handoffOperational(context.Background(), d, peer, f.Request)
	if result.run == "" || result.kind != operationalAccepted && result.kind != operationalAmbiguous {
		t.Fatalf("child did not verify the same assigned original: class=%d write=%d", result.kind, result.write)
	}
	fmt.Printf("ES_OPERATIONAL_CHILD_RESULT %d %s\n", result.kind, result.run)
}

type operationalChild struct {
	input  io.WriteCloser
	result <-chan string
	ready  <-chan struct{}
	held   <-chan struct{}
}

func startOperationalChild(t *testing.T, ctx context.Context, path string) operationalChild {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperationalHandoffChildProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "ES_OPERATIONAL_CHILD_FIXTURE="+path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready, held := make(chan struct{}), make(chan struct{})
	result := make(chan string, 1)
	go func() {
		var lines []string
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			line := scanner.Text()
			lines = append(lines, line)
			if line == "ES_OPERATIONAL_CHILD_READY" {
				close(ready)
			}
			if line == "ES_OPERATIONAL_CHILD_HELD" {
				close(held)
			}
		}
		if err := cmd.Wait(); err != nil {
			lines = append(lines, err.Error())
		}
		if err := scanner.Err(); err != nil {
			lines = append(lines, err.Error())
		}
		result <- strings.Join(lines, "\n")
		close(result)
	}()
	t.Cleanup(func() { _ = in.Close(); <-result })
	return operationalChild{input: in, result: result, ready: ready, held: held}
}

func awaitOperationalChild(t *testing.T, ctx context.Context, child operationalChild) (operationalResultKind, string) {
	t.Helper()
	select {
	case logs := <-child.result:
		if !strings.Contains(logs, "--- PASS: TestOperationalHandoffChildProcess") {
			t.Fatalf("child did not reach assertions:\n%s", logs)
		}
		for _, line := range strings.Split(logs, "\n") {
			if strings.HasPrefix(line, "ES_OPERATIONAL_CHILD_RESULT ") {
				var kind uint8
				var run string
				if _, err := fmt.Sscan(strings.TrimPrefix(line, "ES_OPERATIONAL_CHILD_RESULT "), &kind, &run); err != nil {
					t.Fatal(err)
				}
				return operationalResultKind(kind), run
			}
		}
		t.Fatal("child result sentinel missing")
	case <-ctx.Done():
		t.Fatal("child result timeout")
	}
	return operationalUnavailable, ""
}

func testOperationalTwoProcesses(t *testing.T, winner int) {
	t.Helper()
	f := makeOperationalFixture(t, "")
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
		t.Fatal(err)
	}
	seed := f.submit()
	if seed.write != reliablesubmit.OperationalOwnCommitConfirmed || seed.run == "" {
		t.Fatalf("pre-stage seed: %d", seed.write)
	}
	f.receiver.entered = make(chan struct{}, 1)
	f.receiver.release = make(chan struct{})
	defer func() {
		select {
		case <-f.receiver.release:
		default:
			close(f.receiver.release)
		}
	}()
	raw, err := json.Marshal(f.childFixture())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "same-domain.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	children := []operationalChild{startOperationalChild(t, ctx, path), startOperationalChild(t, ctx, path)}
	for _, child := range children {
		select {
		case <-child.ready:
		case logs := <-child.result:
			t.Fatalf("child failed before readiness: %s", logs)
		case <-ctx.Done():
			t.Fatal("readiness timeout")
		}
	}
	_, err = fmt.Fprintln(children[winner].input, "go")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.receiver.entered:
	case logs := <-children[winner].result:
		t.Fatalf("winner stopped before transport: %s", logs)
	case <-ctx.Done():
		t.Fatal("POST entry timeout")
	}
	if _, err := fmt.Fprintln(children[1-winner].input, "go"); err != nil {
		t.Fatal(err)
	}
	k, other := awaitOperationalChild(t, ctx, children[1-winner])
	if k != operationalAmbiguous || other != seed.run {
		t.Fatal("second process did not observe marked same-run ambiguity")
	}
	close(f.receiver.release)
	k, run := awaitOperationalChild(t, ctx, children[winner])
	if k != operationalAccepted || run != seed.run {
		t.Fatal("winner did not prove registration")
	}
	posts, _, redirects := f.receiver.counts()
	if posts != 1 || redirects != 0 {
		t.Fatalf("both processes had %d POSTs and %d redirect deliveries", posts, redirects)
	}
	t.Log("both independently opened processes reached assertions with one receiver POST")
}

func testOperationalHandoffKnownMarkerBeforeCanceledSend(t *testing.T) {
	f := makeOperationalFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beforeStagingHandoffValidationForTest = func(_ *stagingCustody) {
		var revision int
		if f.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&revision) == nil && revision == 5 {
			cancel()
		}
	}
	defer func() { beforeStagingHandoffValidationForTest = nil }()
	first := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
	if first.write != reliablesubmit.OperationalAppliedReleaseFailed {
		t.Fatalf("marker disposition=%d", first.write)
	}
	d := f.reopen()
	again := (&Service{}).handoffOperational(context.Background(), d, d.caller, f.raw)
	if posts, _, _ := f.receiver.counts(); posts != 0 || again.kind != operationalAmbiguous || again.run == "" {
		t.Fatalf("known marker replay phase=%d posts=%d", again.kind, posts)
	}
}

func testOperationalHandoffQualifiedEpochBlocksEffectsOnChangedPolicy(t *testing.T) {
	f := makeOperationalFixture(t, "")
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
		t.Fatal(err)
	}
	before := f.submit()
	if before.write != reliablesubmit.OperationalOwnCommitConfirmed {
		t.Fatal("prestage seed not confirmed")
	}
	d := f.reopen()
	d.realm.epoch++
	next := (&Service{}).handoffOperational(context.Background(), d, d.caller, f.raw)
	entries, err := os.ReadDir(d.realm.staging)
	posts, gets, _ := f.receiver.counts()
	if err != nil || len(entries) != 0 || next.kind != operationalUnavailable || next.run != "" || posts != 0 || gets != 0 {
		t.Fatalf("changed qualification admitted effects: %d posts=%d observations=%d", next.kind, posts, gets)
	}
}

func testOperationalStageTamper(t *testing.T) {
	t.Run("StagedPayloadChangedAtMarkerCut", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		changed := false
		beforeStagingHandoffValidationForTest = func(c *stagingCustody) {
			var revision int
			if !changed && f.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&revision) == nil && revision == 4 {
				path := filepath.Join(f.domain.realm.staging, c.runID, "payload", "artifact.tar.gz")
				if err := os.WriteFile(path, []byte("changed retained proof artifact"), 0o600); err != nil {
					t.Fatal(err)
				}
				changed = true
			}
		}
		defer func() { beforeStagingHandoffValidationForTest = nil }()
		first := f.submit()
		if !changed || first.kind == operationalAccepted {
			t.Fatal("marker cut failed to exercise changed stage contents")
		}
		reopened := f.reopen()
		again := f.service.handoffOperational(context.Background(), reopened, reopened.caller, f.raw)
		posts, gets, _ := f.receiver.counts()
		var rev int
		if err := f.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&rev); err != nil || rev != 4 || posts != 0 || gets != 0 || again.kind == operationalAccepted {
			t.Fatalf("changed stage advanced rev=%d posts=%d gets=%d error=%v", rev, posts, gets, err)
		}
	})
	t.Run("RetainedStampWithoutThePhysicalStage", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalStamp, false); err != nil {
			t.Fatal(err)
		}
		first := f.submit()
		if first.write != reliablesubmit.OperationalOwnCommitConfirmed || first.run == "" {
			t.Fatal("did not retain the stamp")
		}
		original := filepath.Join(f.domain.realm.staging, first.run)
		residue := filepath.Join(filepath.Dir(f.domain.realm.staging), "retained-stage-for-proof")
		if err := os.Rename(original, residue); err != nil {
			t.Fatal(err)
		}
		reopened := f.reopen()
		again := f.service.handoffOperational(context.Background(), reopened, reopened.caller, f.raw)
		posts, gets, _ := f.receiver.counts()
		if _, err := os.Lstat(original); !os.IsNotExist(err) || posts != 0 || gets != 0 || again.run != first.run || again.kind != operationalPending {
			t.Fatalf("missing stage was replaced or admitted: phase=%d posts=%d gets=%d error=%v", again.kind, posts, gets, err)
		}
	})
}

func testOperationalConcurrentReceipt(t *testing.T) {
	f := makeOperationalFixture(t, "")
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalAccept, true); err != nil {
		t.Fatal(err)
	}
	first := f.submit()
	if first.kind != operationalAmbiguous || first.write != reliablesubmit.OperationalDefinitelyNotApplied {
		t.Fatalf("did not leave a positively observable marker: %d %d", first.kind, first.write)
	}

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	f.receiver.mu.Lock()
	f.receiver.observeEntered, f.receiver.observeRelease = entered, release
	f.receiver.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	domains := []*operationalDomain{f.reopen(), f.reopen()}
	results := make(chan operationalHandoffResult, len(domains))
	var workers sync.WaitGroup
	defer workers.Wait()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	for _, domain := range domains {
		workers.Add(1)
		go func(d *operationalDomain) {
			defer workers.Done()
			results <- (&Service{}).recoverOperational(ctx, d, d.caller, f.raw)
		}(domain)
	}
	for range domains {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("both reconcilers did not reach evaluation ingress")
		}
	}
	unblock()
	one, two := <-results, <-results
	posts, gets, _ := f.receiver.counts()
	if one.kind != operationalAccepted || two.kind != operationalAccepted || one.run != first.run || two.run != first.run ||
		!one.receipt.Valid() || !one.receipt.Equal(two.receipt) || posts != 1 || gets != 6 {
		t.Fatalf("receipt winner mismatch: outcomes=%d/%d writes=%d/%d posts=%d gets=%d", one.kind, two.kind, one.write, two.write, posts, gets)
	}
	direct := one.write == reliablesubmit.OperationalApplied && two.write == reliablesubmit.OperationalStale
	other := two.write == reliablesubmit.OperationalApplied && one.write == reliablesubmit.OperationalStale
	if !direct && !other {
		t.Fatalf("expected exactly one receipt writer and one authenticated stale reader: %d and %d", one.write, two.write)
	}
}

type operationalPrestageState struct {
	Claims, Revision, Grants, StageEntries, Posts, Gets, Redirects int
	RowID                                                          int64
	Intent, Stamp, Marker, Receipt, Materialized                   bool
}

func operationalPrestageStateAt(t *testing.T, f *operationalFixture) operationalPrestageState {
	t.Helper()
	var s operationalPrestageState
	if err := f.db.QueryRow("SELECT count(*) FROM reliable_submit_claims").Scan(&s.Claims); err != nil {
		t.Fatal(err)
	}
	if s.Claims == 1 {
		var intent, stamp, marker, receipt int
		if err := f.db.QueryRow("SELECT claim_rowid, revision, effect_intent_ref IS NOT NULL, staging_ref IS NOT NULL, dispatch_ref IS NOT NULL, receipt_ref IS NOT NULL FROM reliable_submit_claims").Scan(&s.RowID, &s.Revision, &intent, &stamp, &marker, &receipt); err != nil {
			t.Fatal(err)
		}
		s.Intent, s.Stamp, s.Marker, s.Receipt = intent != 0, stamp != 0, marker != 0, receipt != 0
	}
	if err := f.db.QueryRow("SELECT coalesce(sum(granted_count),0) FROM reliable_submit_seal_use").Scan(&s.Grants); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.domain.realm.staging)
	if err != nil {
		t.Fatal(err)
	}
	s.StageEntries = len(entries)
	if len(entries) > 0 {
		_, err = os.Stat(filepath.Join(f.domain.realm.staging, entries[0].Name(), "payload", "artifact.tar.gz"))
		s.Materialized = err == nil
	}
	s.Posts, s.Gets, s.Redirects = f.receiver.counts()
	return s
}

func operationalSealedDigest(t *testing.T, f *operationalFixture) [32]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("sealed original inventory: %d %v", len(entries), err)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "objects", "v1", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func testOperationalHandoffPrestageCleanup(t *testing.T) {
	for _, setup := range []string{"fresh", "existing"} {
		for _, variant := range []string{"success", "modeled-release-response", "modeled-rollback-response", "caller-canceled", "key-denied", "stale-winner"} {
			if setup == "existing" && (variant == "key-denied" || variant == "stale-winner") {
				continue
			}
			t.Run(setup+"/"+variant, func(t *testing.T) {
				f := makeOperationalFixture(t, "positive")
				if setup == "existing" {
					if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
						t.Fatal(err)
					}
					first := f.submit()
					if first.operation != reliablesubmit.OperationalIntent || first.write != reliablesubmit.OperationalOwnCommitConfirmed || first.run == "" {
						t.Fatalf("existing revision-3 setup: %+v", first)
					}
					f.domain = f.reopen()
					if state := operationalPrestageStateAt(t, f); state.Revision != 3 || state.StageEntries != 0 || state.Posts != 0 {
						t.Fatalf("existing setup state: %+v", state)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx, getConn := operationalGetConnEventsOn(ctx)
				var postEntry, getEntry atomic.Int32
				f.domain.provider.exchangeEntry = func(method string) {
					if method == http.MethodPost {
						postEntry.Add(1)
					} else if method == http.MethodGet {
						getEntry.Add(1)
					}
				}
				defer func() { f.domain.provider.exchangeEntry = nil }()
				var events []string
				stageAttempts, materializeAttempts := 0, 0
				var prestage reliablesubmit.OperationalCheck
				observed := false
				proof := reliablesubmit.OperationalPrestageProofHooks{
					AfterSemantic: func() { events = append(events, "semantic") },
					AfterRollback: func(ok bool) bool {
						if !ok {
							t.Fatal("real rollback failed")
						}
						events = append(events, "rollback")
						return variant == "modeled-rollback-response"
					},
					AfterRelease: func(ok bool) bool {
						if !ok {
							t.Fatal("real close failed")
						}
						events = append(events, "release")
						if variant == "caller-canceled" {
							cancel()
						}
						return variant == "modeled-release-response"
					},
					Observe: func(check reliablesubmit.OperationalCheck) {
						prestage = check
						observed = true
						events = append(events, "result")
					},
				}
				if err := f.domain.custody.ConfigureOperationalPrestageProofForProof(proof); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = f.domain.custody.ConfigureOperationalPrestageProofForProof(reliablesubmit.OperationalPrestageProofHooks{})
				})
				var before operationalPrestageState
				var beforePostEntry, beforeGetEntry, beforeGetConn int32
				var sealed [32]byte
				reached := false
				f.domain.proof = &operationalHandoffProofHooks{beforeStageCreate: func() { stageAttempts++ }, beforeMaterialize: func() { materializeAttempts++ }, beforePrestage: func() {
					reached = true
					switch variant {
					case "key-denied":
						if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=3 WHERE purpose=1"); err != nil {
							t.Fatal(err)
						}
					case "stale-winner":
						other := f.reopen()
						winner := f.service.handoffOperational(context.Background(), other, other.caller, f.raw)
						if winner.kind != operationalAccepted {
							t.Fatalf("independent winner=%v", winner.kind)
						}
					}
					before = operationalPrestageStateAt(t, f)
					beforePostEntry, beforeGetEntry, beforeGetConn = postEntry.Load(), getEntry.Load(), getConn.Load()
					sealed = operationalSealedDigest(t, f)
				}}
				out := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
				after := operationalPrestageStateAt(t, f)
				if !reached || !observed || before.RowID <= 0 || before.Grants != 1 || !before.Intent || !reflect.DeepEqual(sealed, operationalSealedDigest(t, f)) {
					t.Fatalf("unqualified diagnostic: reached=%t observed=%t before=%+v", reached, observed, before)
				}
				if after.Claims != 1 || after.RowID != before.RowID || after.Grants != before.Grants {
					t.Fatalf("claim/charge changed: before=%+v after=%+v", before, after)
				}
				if setup == "fresh" && (variant == "key-denied" || variant == "stale-winner") && (out.operation != reliablesubmit.OperationalIntent || out.write != reliablesubmit.OperationalApplied) {
					t.Fatalf("fresh intent knowledge lost: operation=%v write=%v", out.operation, out.write)
				}
				if setup == "existing" && variant != "success" && (out.operation != 0 || out.write != 0) {
					t.Fatalf("read-only invocation invented write: operation=%v write=%v", out.operation, out.write)
				}
				t.Logf("prestage setup=%s variant=%s disposition=%d reason=%d events=%v result=%d/%d operation=%d write=%d before=%+v after=%+v stageAttempts=%d materializeAttempts=%d POSTentry=%d GETentry=%d GetConn=%d baselineEntry=%d/%d baselineGetConn=%d", setup, variant, prestage.Disposition(), prestage.Reason(), events, out.kind, out.reason, out.operation, out.write, before, after, stageAttempts, materializeAttempts, postEntry.Load(), getEntry.Load(), getConn.Load(), beforePostEntry, beforeGetEntry, beforeGetConn)
				switch variant {
				case "success":
					if prestage.Disposition() != reliablesubmit.OperationalNoChange || prestage.Reason() != reliablesubmit.OperationalReasonNone || !reflect.DeepEqual(events, []string{"semantic", "rollback", "release", "result"}) || stageAttempts != 1 || materializeAttempts != 1 || out.kind != operationalAccepted || after.Revision != 6 || after.StageEntries != 1 || !after.Materialized || !after.Marker || !after.Receipt || after.Posts != 1 || postEntry.Load() != 1 || getEntry.Load() != int32(after.Gets) || getConn.Load() != int32(after.Posts+after.Gets) {
						t.Fatalf("positive control failed: %+v", after)
					}
				case "modeled-release-response", "modeled-rollback-response", "caller-canceled":
					want := reliablesubmit.OperationalClosed
					if variant == "caller-canceled" {
						want = reliablesubmit.OperationalCanceled
					}
					wantEvents := []string{"semantic", "rollback", "release", "result"}
					if variant == "modeled-rollback-response" {
						wantEvents = []string{"semantic", "rollback", "result"}
					}
					if prestage.Disposition() != reliablesubmit.OperationalNoChange || prestage.Reason() != want || !reflect.DeepEqual(events, wantEvents) || stageAttempts != 0 || materializeAttempts != 0 || out.kind != operationalUnavailable || out.reason != want || out.run != "" || out.receipt.Valid() || after.Revision != 3 || after.Stamp || after.Marker || after.Receipt || after.StageEntries != before.StageEntries || after.Materialized || after.Posts != before.Posts || postEntry.Load() != 0 || getEntry.Load() != 0 || getConn.Load() != 0 {
						t.Fatalf("failed pre-stage continued: before=%+v after=%+v result=%+v", before, after, out)
					}
					if setup == "fresh" && (out.operation != reliablesubmit.OperationalIntent || out.write != reliablesubmit.OperationalApplied) {
						t.Fatalf("fresh failed pre-stage erased intent knowledge: operation=%v write=%v", out.operation, out.write)
					}
				case "key-denied", "stale-winner":
					if prestage.Disposition() == reliablesubmit.OperationalNoChange || len(events) != 1 || stageAttempts != 0 || materializeAttempts != 0 || after.StageEntries != before.StageEntries || after.Posts != before.Posts || after.Revision != before.Revision || postEntry.Load() != beforePostEntry || getEntry.Load() != beforeGetEntry || getConn.Load() != beforeGetConn || out.run != "" || out.receipt.Valid() {
						t.Fatalf("denied/stale cut continued: before=%+v after=%+v", before, after)
					}
				}
			})
		}
	}
}
