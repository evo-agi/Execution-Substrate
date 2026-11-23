package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"execution-substrate/es/admission/internal/reliablesubmit"
	"golang.org/x/sys/unix"
)

func privateReplayTestRoot(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(parentFD, "synthetic", 0o700); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Openat(parentFD, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(rootFD, "objects", 0o700); err != nil {
		t.Fatal(err)
	}
	objectsFD, err := unix.Openat(rootFD, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(objectsFD, "v1", 0o700); err != nil {
		t.Fatal(err)
	}
	v1FD, err := unix.Openat(objectsFD, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	markerFD, err := unix.Openat(rootFD, "synthetic-replay-v1.marker", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("synthetic_nonoperational_v1\n")
	if n, err := unix.Write(markerFD, marker); err != nil || n != len(marker) {
		t.Fatal("write synthetic marker")
	}
	if err := unix.Fsync(markerFD); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(markerFD); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{v1FD, objectsFD, rootFD, parentFD} {
		if err := unix.Fsync(fd); err != nil {
			t.Fatal(err)
		}
	}
	// Reopen through the visible path and compare the held final directory.
	visibleObjects, err := unix.Openat(rootFD, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	visible, err := unix.Openat(visibleObjects, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var heldStat, visibleStat unix.Stat_t
	if unix.Fstat(v1FD, &heldStat) != nil || unix.Fstat(visible, &visibleStat) != nil || heldStat.Dev != visibleStat.Dev || heldStat.Ino != visibleStat.Ino {
		t.Fatal("synthetic directory identity changed")
	}
	if err := unix.Close(visible); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(visibleObjects); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{v1FD, objectsFD, rootFD, parentFD} {
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(parent, "synthetic")
}

func openPrivateReplayTestCustody(t *testing.T) (*reliablesubmit.PrivateReplayCustody, string) {
	t.Helper()
	root := privateReplayTestRoot(t)
	custody, err := reliablesubmit.OpenPrivateReplayCustody(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return custody, root
}

func privateReplayServiceFixture(t *testing.T) (*Service, []byte, syntheticCallerFact, privateSyntheticKeyBundle, privateSyntheticImagePlacement) {
	t.Helper()
	fixture := newPreparedArtifactFixture(t)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixture, payload)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, payload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("private replay reached provider registration") }))
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	request := fixture.prepareRequest()
	raw, err := json.Marshal(map[string]any{
		"schema_version":  reliableSubmitRequestSchemaV1,
		"reliable_submit": map[string]any{"contract": reliableSubmitContractV1, "submit_key": key},
		"invocation":      request.Invocation,
	})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := newSyntheticCallerFact("spiffe://synthetic.test/ns/admission")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := newPrivateSyntheticKeyBundle("Binding-A", bytes.Repeat([]byte{0x41}, 32), "Envelope-A", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	image, err := newPrivateSyntheticImagePlacement(bytes.Repeat([]byte{0x51}, 32), "synthetic-image-issuer")
	if err != nil {
		t.Fatal(err)
	}
	return service, raw, caller, keys, image
}

func TestPrivateReplaySameDeliveryPB1Verification(t *testing.T) {
	service, raw, caller, keys, image := privateReplayServiceFixture(t)
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		t.Fatalf("strict parse: %v", err)
	}
	proposal, err := service.composePrivateSyntheticReplay(context.Background(), delivery, keys, image, 1)
	if err != nil {
		t.Fatalf("same-delivery resolver and PB1 composer: %v", err)
	}
	if !proposal.originalIntent.invocationPresent {
		t.Fatal("composer lost original intent")
	}
	custody, _ := openPrivateReplayTestCustody(t)
	defer custody.Close()
	grant, err := custody.ReserveSealUse(context.Background(), proposal.frozen)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	publication, err := custody.PublishSealedSynthetic(context.Background(), proposal.frozen, grant)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	attempt, created, err := custody.EstablishSyntheticClaim(context.Background(), proposal.frozen, publication)
	if err != nil || !created {
		t.Fatalf("establish created=%v err=%v", created, err)
	}
	called := false
	err = custody.WithAuthenticatedClaim(context.Background(), delivery.refs.claimID, keys.storage, func(meta reliablesubmit.AuthenticatedClaimMeta, plaintext []byte) error {
		verified, verifyErr := verifyPrivateReplayOriginal(meta, plaintext, keys)
		if verifyErr != nil {
			return verifyErr
		}
		if !verified.claim.Equal(delivery.refs.claimID) || !meta.MatchesAttempt(attempt) {
			t.Fatal("verified original association mismatch")
		}
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("admission verified reload: %v called=%v", err, called)
	}
}

func TestPrivateReplayWinnerOriginalAfterDefaultKeyDrift(t *testing.T) {
	ctx := context.Background()
	service, raw, caller, original, image := privateReplayServiceFixture(t)
	custody, _ := openPrivateReplayTestCustody(t)
	defer custody.Close()
	firstCatalog, err := newPrivateSyntheticKeyCatalog(original)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, firstCatalog, image)
	if err != nil || first.kind != privateReplayEstablished {
		t.Fatalf("first synthetic claim: kind=%d err=%v", first.kind, err)
	}
	rotated, err := newPrivateSyntheticKeyBundle("Binding-B", bytes.Repeat([]byte{0x43}, 32), "Envelope-B", bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := newPrivateSyntheticKeyCatalog(rotated, original)
	if err != nil {
		t.Fatal(err)
	}
	// A retry must not observe the now-unavailable resolver or choose B.
	service.arsClient = nil
	service.nomadClient = nil
	replay, err := service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, secondCatalog, image)
	if err != nil || replay.kind != privateReplayExact {
		t.Fatalf("verified original retry: kind=%d err=%v", replay.kind, err)
	}
	if !replay.verified.claim.Equal(first.verified.claim) {
		t.Fatal("original claim changed")
	}
	changed := append([]byte(nil), raw...)
	changed = bytes.Replace(changed, []byte(`"output_id":"`), []byte(`"output_id":"changed-`), 1)
	conflict, err := service.admitPrivateSyntheticReplay(ctx, custody, changed, caller, secondCatalog, image)
	if err != errPrivateReplayConflict || conflict.kind != privateReplayConflict {
		t.Fatalf("changed intent kind=%d err=%v", conflict.kind, err)
	}
}

// privateReplayClaimRendezvousBound limits how long a concurrent replay test
// waits for its workers, so a worker that never reaches the claim fails the
// test instead of blocking it until the package timeout.
const privateReplayClaimRendezvousBound = 8 * time.Second

// privateReplayClaimRendezvous holds concurrent private replay admissions at
// the pre-claim test hook until every one has arrived, then releases them
// together, so the claim race is real.
type privateReplayClaimRendezvous struct {
	want         int
	arrivalBound time.Duration
	arrived      chan struct{}
	release      chan struct{}
	returned     chan struct{}
	workers      sync.WaitGroup
}

func newPrivateReplayClaimRendezvous(want int) *privateReplayClaimRendezvous {
	r := &privateReplayClaimRendezvous{
		want:         want,
		arrivalBound: privateReplayClaimRendezvousBound,
		arrived:      make(chan struct{}, want),
		release:      make(chan struct{}),
		returned:     make(chan struct{}, want),
	}
	beforePrivateReplayClaimForTest = func() { r.arrived <- struct{}{}; <-r.release }
	return r
}

func (r *privateReplayClaimRendezvous) uninstall() {
	beforePrivateReplayClaimForTest = nil
}

// start runs one admission worker and records when it returns.
func (r *privateReplayClaimRendezvous) start(work func()) {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		defer func() { r.returned <- struct{}{} }()
		work()
	}()
}

// releaseAndWait waits until every worker has reached the claim hook, releases
// them, and waits for all of them to return. A worker that returns before
// reaching the hook, for example because admission failed earlier, or a
// rendezvous that does not complete within the bound, does not block: the hook
// is released anyway and the returned text says what was incomplete, so the
// caller can first report each worker's own error. Workers that still have not
// returned within the bound after the release fail the test at once.
func (r *privateReplayClaimRendezvous) releaseAndWait(t *testing.T) string {
	t.Helper()
	arrivalDeadline := time.NewTimer(r.arrivalBound)
	defer arrivalDeadline.Stop()
	reached := 0
	incomplete := ""
	for reached < r.want && incomplete == "" {
		select {
		case <-r.arrived:
			reached++
		case <-r.returned:
			incomplete = fmt.Sprintf("a concurrent admission returned before reaching the claim (%d of %d reached)", reached, r.want)
		case <-arrivalDeadline.C:
			incomplete = fmt.Sprintf("concurrent admissions did not reach the claim within %s (%d of %d reached)", r.arrivalBound, reached, r.want)
		}
	}
	close(r.release)
	done := make(chan struct{})
	go func() {
		r.workers.Wait()
		close(done)
	}()
	returnDeadline := time.NewTimer(privateReplayClaimRendezvousBound)
	defer returnDeadline.Stop()
	select {
	case <-done:
	case <-returnDeadline.C:
		t.Fatalf("concurrent admissions did not return within %s after release (%s)", privateReplayClaimRendezvousBound, incomplete)
	}
	return incomplete
}

func TestPrivateReplayClaimRendezvousReportsAWorkerThatReturnsEarly(t *testing.T) {
	rendezvous := newPrivateReplayClaimRendezvous(2)
	defer rendezvous.uninstall()
	hook := beforePrivateReplayClaimForTest
	rendezvous.start(func() {})
	rendezvous.start(func() { hook() })
	started := time.Now()
	incomplete := rendezvous.releaseAndWait(t)
	if !strings.Contains(incomplete, "returned before reaching the claim") {
		t.Fatalf("early worker return was not reported: %q", incomplete)
	}
	if elapsed := time.Since(started); elapsed >= privateReplayClaimRendezvousBound {
		t.Fatalf("early worker return was reported only after the bound: %s", elapsed)
	}
}

// TestPrivateReplayClaimRendezvousBoundsTheWaitForArrival holds one worker
// short of the claim hook until the release, so only the arrival bound can end
// the wait. The rendezvous must report it and release the worker instead of
// waiting for an arrival that never comes.
func TestPrivateReplayClaimRendezvousBoundsTheWaitForArrival(t *testing.T) {
	rendezvous := newPrivateReplayClaimRendezvous(2)
	defer rendezvous.uninstall()
	rendezvous.arrivalBound = 50 * time.Millisecond
	hook := beforePrivateReplayClaimForTest
	rendezvous.start(func() { hook() })
	rendezvous.start(func() { <-rendezvous.release })
	result := make(chan string, 1)
	go func() { result <- rendezvous.releaseAndWait(t) }()
	select {
	case incomplete := <-result:
		if !strings.Contains(incomplete, "did not reach the claim within 50ms (1 of 2 reached)") {
			t.Fatalf("missing arrival was not reported: %q", incomplete)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the rendezvous waited past its arrival bound for a worker that never reached the claim")
	}
}

func TestPrivateReplayConcurrentWinnerClassification(t *testing.T) {
	t.Run("same_facts_positive_control", func(t *testing.T) {
		ctx := context.Background()
		service, raw, caller, keys, image := privateReplayServiceFixture(t)
		custody, root := openPrivateReplayTestCustody(t)
		defer custody.Close()
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		rendezvous := newPrivateReplayClaimRendezvous(2)
		defer rendezvous.uninstall()
		type classified struct {
			kind privateReplayResultKind
			err  error
		}
		results := make(chan classified, 2)
		for i := 0; i < 2; i++ {
			rendezvous.start(func() {
				result, err := service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, catalog, image)
				results <- classified{kind: result.kind, err: err}
			})
		}
		incomplete := rendezvous.releaseAndWait(t)
		close(results)
		counts := map[privateReplayResultKind]int{}
		for result := range results {
			if result.err != nil {
				t.Fatalf("concurrent admission: %v", result.err)
			}
			counts[result.kind]++
		}
		if incomplete != "" {
			t.Fatal(incomplete)
		}
		if counts[privateReplayEstablished] != 1 || counts[privateReplayWinner] != 1 || len(counts) != 2 {
			t.Fatalf("unexpected synthetic winner classification: %v", counts)
		}
		entries, err := os.ReadDir(filepath.Join(root, "objects", "v1"))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatalf("winning and losing sealed proposals=%d", len(entries))
		}
	})
	t.Run("drifted_defaults_image_placement_and_keys", func(t *testing.T) {
		ctx := context.Background()
		firstService, raw, caller, firstKeys, firstImage := privateReplayServiceFixture(t)
		// Construct a distinct service with a fresh mutex. Its controlled
		// dependencies serve the same signed artifact, while defaults drift.
		secondService := &Service{
			cfg: firstService.cfg, resultAuth: firstService.resultAuth,
			workloadZoneVaultConfigRef: firstService.workloadZoneVaultConfigRef,
			arsClient:                  firstService.arsClient, egsClient: firstService.egsClient,
			trustModelVerifier:       firstService.trustModelVerifier,
			provenanceVerifier:       firstService.provenanceVerifier,
			nomadClient:              firstService.nomadClient,
			admissionPolicyEvaluator: firstService.admissionPolicyEvaluator,
			trustModel:               firstService.trustModel,
		}
		secondService.cfg.Execution.BaseImage = "synthetic-drift-image-b"
		secondService.cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Image = "synthetic-drift-image-b"
		secondService.cfg.Nomad.Datacenter = "synthetic-drift-dc-b"
		secondKeys, err := newPrivateSyntheticKeyBundle("Binding-B", bytes.Repeat([]byte{0x43}, 32), "Envelope-B", bytes.Repeat([]byte{0x44}, 32))
		if err != nil {
			t.Fatal(err)
		}
		secondImage, err := newPrivateSyntheticImagePlacement(bytes.Repeat([]byte{0x52}, 32), "synthetic-image-issuer-b")
		if err != nil {
			t.Fatal(err)
		}
		firstCatalog, err := newPrivateSyntheticKeyCatalog(firstKeys, secondKeys)
		if err != nil {
			t.Fatal(err)
		}
		secondCatalog, err := newPrivateSyntheticKeyCatalog(secondKeys, firstKeys)
		if err != nil {
			t.Fatal(err)
		}
		firstImageRef := strings.TrimSpace(firstService.cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Image)
		if firstImageRef == "" {
			firstImageRef = strings.TrimSpace(firstService.cfg.Execution.BaseImage)
		}
		if firstImageRef == "synthetic-drift-image-b" || strings.TrimSpace(firstService.cfg.Nomad.Datacenter) == "synthetic-drift-dc-b" || firstImage.contentDigest == secondImage.contentDigest {
			t.Fatal("controlled first proposals did not have different facts")
		}
		delivery, err := parsePrivateReplayDelivery(raw, caller)
		if err != nil {
			t.Fatal(err)
		}
		firstResolved, firstResolveErr := firstService.resolveExecutionForSubmit(ctx, delivery.request)
		if firstResolveErr != nil {
			t.Fatal("first controlled resolver failed")
		}
		secondResolved, secondResolveErr := secondService.resolveExecutionForSubmit(ctx, delivery.request)
		if secondResolveErr != nil {
			t.Fatal("second controlled resolver failed")
		}
		if firstResolved.plan.runtimeProfile.image == secondResolved.plan.runtimeProfile.image ||
			firstResolved.host.datacenter == secondResolved.host.datacenter ||
			secondResolved.plan.runtimeProfile.image != "synthetic-drift-image-b" ||
			secondResolved.host.datacenter != "synthetic-drift-dc-b" {
			t.Fatal("independent real resolver facts did not drift")
		}
		custody, root := openPrivateReplayTestCustody(t)
		defer custody.Close()
		initialClaim, err := custody.LoadSyntheticClaim(ctx, delivery.refs.claimID)
		if err != nil || initialClaim.Found() {
			t.Fatalf("fresh claim was not absent: %v", err)
		}
		assertDirectoryEmpty(t, firstService.cfg.Execution.StagingRootDir)
		assertDirectoryEmpty(t, firstService.cfg.Execution.ResultsRootDir)
		rendezvous := newPrivateReplayClaimRendezvous(2)
		defer rendezvous.uninstall()
		type classified struct {
			index  int
			result privateReplayResult
			err    error
		}
		results := make(chan classified, 2)
		for index, candidate := range []struct {
			service *Service
			catalog privateSyntheticKeyCatalog
			image   privateSyntheticImagePlacement
		}{
			{firstService, firstCatalog, firstImage},
			{secondService, secondCatalog, secondImage},
		} {
			rendezvous.start(func() {
				result, err := candidate.service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, candidate.catalog, candidate.image)
				results <- classified{index: index, result: result, err: err}
			})
		}
		incomplete := rendezvous.releaseAndWait(t)
		close(results)
		var outcomes [2]classified
		for outcome := range results {
			if outcome.err != nil {
				t.Fatalf("drifted concurrent admission: %v", outcome.err)
			}
			outcomes[outcome.index] = outcome
		}
		if incomplete != "" {
			t.Fatal(incomplete)
		}
		winner := -1
		if outcomes[0].result.kind == privateReplayEstablished && outcomes[1].result.kind == privateReplayWinner {
			winner = 0
		} else if outcomes[1].result.kind == privateReplayEstablished && outcomes[0].result.kind == privateReplayWinner {
			winner = 1
		} else {
			t.Fatalf("drifted winner kinds=%d/%d", outcomes[0].result.kind, outcomes[1].result.kind)
		}
		loser := 1 - winner
		winnerFacts := outcomes[winner].result.verified
		loserFacts := outcomes[loser].result.verified
		wantImageRef := firstImageRef
		wantDatacenter := strings.TrimSpace(firstService.cfg.Nomad.Datacenter)
		wantKeys := firstKeys
		wantImage := firstImage
		loseImageRef := "synthetic-drift-image-b"
		loseDatacenter := "synthetic-drift-dc-b"
		if winner == 1 {
			wantImageRef, loseImageRef = loseImageRef, wantImageRef
			wantDatacenter, loseDatacenter = loseDatacenter, wantDatacenter
			wantKeys, wantImage = secondKeys, secondImage
		}
		if !winnerFacts.claim.Valid() || !winnerFacts.claim.Equal(loserFacts.claim) ||
			winnerFacts.resolved.plan.runtimeProfile.image != wantImageRef ||
			winnerFacts.resolved.host.datacenter != wantDatacenter ||
			loserFacts.resolved.plan.runtimeProfile.image != wantImageRef ||
			loserFacts.resolved.host.datacenter != wantDatacenter ||
			loserFacts.resolved.plan.runtimeProfile.image == loseImageRef ||
			loserFacts.resolved.host.datacenter == loseDatacenter ||
			!loserFacts.assessment.boundPlan.EqualBinding(winnerFacts.assessment.boundPlan.Binding()) ||
			!privateOriginalIntentEqual(winnerFacts.intentCanonical, loserFacts.intentCanonical) ||
			winnerFacts.assessment.effectReady || loserFacts.assessment.effectReady ||
			!winnerFacts.ownAttempt || loserFacts.ownAttempt {
			t.Fatal("loser did not expose verified winner-original facts")
		}
		lookup, err := custody.LoadSyntheticClaim(ctx, winnerFacts.claim)
		if err != nil || !lookup.Found() {
			t.Fatalf("single winning claim unavailable: %v", err)
		}
		// The fresh checked database had no claim for this identity. Both
		// proposals use that identity; one Established and one Winner result,
		// followed by this lookup, account for the sole authoritative claim.
		bindingID, envelopeID, ok := lookup.OriginalKeyIDs()
		if !ok || bindingID != wantKeys.bindingID || envelopeID != wantKeys.envelopeID {
			t.Fatal("loser key choice rebound winning claim")
		}
		checkedImage := false
		if err := custody.WithAuthenticatedClaim(ctx, winnerFacts.claim, wantKeys.storage, func(_ reliablesubmit.AuthenticatedClaimMeta, plaintext []byte) error {
			reader := privateReplayReader{}
			fields, err := reader.payload(plaintext)
			if err != nil {
				return err
			}
			retained, err := reader.image(fields[5].value, winnerFacts.resolved.plan, winnerFacts.resolved.host)
			if err != nil || retained.contentDigest != wantImage.contentDigest || retained.issuer != wantImage.issuer {
				return errPrivateReplayUnavailable
			}
			checkedImage = true
			return nil
		}); err != nil || !checkedImage {
			t.Fatalf("winner image proof not retained: %v", err)
		}
		entries, err := os.ReadDir(filepath.Join(root, "objects", "v1"))
		if err != nil || len(entries) != 2 {
			t.Fatalf("drifted proposals did not publish two bounded files: %v", err)
		}
		assertDirectoryEmpty(t, firstService.cfg.Execution.StagingRootDir)
		assertDirectoryEmpty(t, firstService.cfg.Execution.ResultsRootDir)
	})
}

func TestPrivateReplayCommitUnknownOutcomeKinds(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		fault   reliablesubmit.PrivateReplayClaimCommitFault
		want    privateReplayResultKind
		wantErr error
	}{
		{"actual_commit_response_lost", reliablesubmit.PrivateReplayClaimCommitResponseLost, privateReplayOwnUnknownConfirmed, nil},
		{"connection_closed_before_commit", reliablesubmit.PrivateReplayClaimConnectionClosedBeforeCommit, privateReplayUnknown, errPrivateReplayCommitUnknown},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			service, raw, caller, keys, image := privateReplayServiceFixture(t)
			custody, _ := openPrivateReplayTestCustody(t)
			defer custody.Close()
			catalog, err := newPrivateSyntheticKeyCatalog(keys)
			if err != nil {
				t.Fatal(err)
			}
			if err := custody.InjectClaimCommitFaultForTesting(scenario.fault); err != nil {
				t.Fatal(err)
			}
			result, err := service.admitPrivateSyntheticReplay(context.Background(), custody, raw, caller, catalog, image)
			if result.kind != scenario.want || err != scenario.wantErr {
				t.Fatalf("real commit fault kind=%d error=%v", result.kind, err)
			}
			if scenario.want == privateReplayOwnUnknownConfirmed && !result.verified.claim.Valid() {
				t.Fatal("committed original was not reverified")
			}
		})
	}
}

func TestPrivateReplayFreshProcessVerifiedOriginal(t *testing.T) {
	if os.Getenv("ES_REPLAY_FRESH_CHILD") == "1" {
		root := os.Getenv("ES_REPLAY_FRESH_ROOT")
		keyFile := os.Getenv("ES_REPLAY_FRESH_KEY_FILE")
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil || len(keyBytes) != 64 {
			t.Fatal("private key fixture unavailable")
		}
		keys, err := newPrivateSyntheticKeyBundle("Binding-A", keyBytes[:32], "Envelope-A", keyBytes[32:])
		if err != nil {
			t.Fatal("private key fixture invalid")
		}
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		caller, err := newSyntheticCallerFact("spiffe://synthetic.test/ns/admission")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 262145))
		if err != nil || len(raw) > 262144 {
			t.Fatal("private delivery unavailable")
		}
		custody, err := reliablesubmit.OpenPrivateReplayCustody(context.Background(), root)
		if err != nil {
			t.Fatal("fresh custody open failed")
		}
		defer custody.Close()
		result, err := (&Service{}).admitPrivateSyntheticReplay(context.Background(), custody, raw, caller, catalog, privateSyntheticImagePlacement{})
		if err != nil || result.kind != privateReplayExact || !result.verified.claim.Valid() {
			t.Fatal("fresh admission original verification failed")
		}
		fmt.Println("FRESH_VERIFIED_ORIGINAL")
		return
	}
	service, raw, caller, keys, image := privateReplayServiceFixture(t)
	custody, root := openPrivateReplayTestCustody(t)
	catalog, err := newPrivateSyntheticKeyCatalog(keys)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.admitPrivateSyntheticReplay(context.Background(), custody, raw, caller, catalog, image)
	if err != nil || result.kind != privateReplayEstablished {
		t.Fatal("writer failed to establish original")
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(filepath.Dir(root), "synthetic-key-fixture")
	file, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := append(bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32)...)
	if _, err := file.Write(keyBytes); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPrivateReplayFreshProcessVerifiedOriginal$", "-test.v")
	cmd.Env = append(os.Environ(), "ES_REPLAY_FRESH_CHILD=1", "ES_REPLAY_FRESH_ROOT="+root, "ES_REPLAY_FRESH_KEY_FILE="+keyPath)
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "FRESH_VERIFIED_ORIGINAL") || !strings.Contains(string(output), "PASS") {
		t.Fatal("distinct reader process failed original verification")
	}
}

func TestPrivateReplayRedactionAndNonwiring(t *testing.T) {
	service, raw, caller, keys, image := privateReplayServiceFixture(t)
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := service.composePrivateSyntheticReplay(context.Background(), delivery, keys, image, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{caller, delivery, delivery.originalIntent, keys, proposal, proposal.frozen} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, "Binding-A") || strings.Contains(formatted, "spiffe://synthetic") || strings.Contains(formatted, "artifact_digest") {
			t.Fatal("private aggregate formatting leaked synthetic canary")
		}
		encoded, err := json.Marshal(value)
		if err == nil && (bytes.Contains(encoded, []byte("Binding-A")) || bytes.Contains(encoded, []byte("spiffe://synthetic")) || bytes.Contains(encoded, []byte("artifact_digest"))) {
			t.Fatal("private aggregate JSON leaked synthetic canary")
		}
	}
	custody, root := openPrivateReplayTestCustody(t)
	defer custody.Close()
	catalog, err := newPrivateSyntheticKeyCatalog(keys)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.admitPrivateSyntheticReplay(context.Background(), custody, raw, caller, catalog, image)
	if err != nil || result.kind != privateReplayEstablished {
		t.Fatal("synthetic setup failed")
	}
	formatted := fmt.Sprintf("%v %+v %#v", result.verified, result.verified, result.verified)
	if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, "artifact_digest") {
		t.Fatal("verified original formatting leaked")
	}
	for _, path := range []string{filepath.Join(root, "reliable-submit.sqlite3"), filepath.Join(root, "objects", "v1")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				sealed, err := os.ReadFile(filepath.Join(path, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(sealed, raw) {
					t.Fatal("raw request JSON appeared in sealed object")
				}
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, raw) || bytes.Contains(data, bytes.Repeat([]byte{0x31}, 32)) {
			t.Fatal("raw request or submit key persisted")
		}
	}
	bad := append([]byte(nil), raw...)
	bad = append(bad, []byte(` "private-secret-canary"`)...)
	if _, err := service.admitPrivateSyntheticReplay(context.Background(), custody, bad, caller, catalog, image); err == nil || strings.Contains(err.Error(), "private-secret-canary") {
		t.Fatal("invalid private delivery disclosed canary")
	}
}

func TestPrivateReplayFiniteCallerAndNoRuntimeWiring(t *testing.T) {
	views := loadTypedProductionPackages(t, "./es/admission")
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		for _, name := range []string{"buildReliableSubmitAdmissionBinding", "newReliableBindingFamily"} {
			if pkg.pkg.Scope().Lookup(name) == nil {
				t.Fatalf("missing selected private helper %s", name)
			}
		}
		refs := pkg.referencesTo(requirePackageFunction(t, pkg, "buildReliableSubmitAdmissionBinding"))
		want := privateBindingCallerInventory()
		if err := validateTypedReferenceInventory("private PB1 caller closure", refs, want, true); err != nil {
			t.Fatal(err)
		}
		var operational typedReference
		for _, ref := range refs {
			if ref.site == "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal" {
				operational = ref
			}
		}
		if operational.site == "" {
			t.Fatal("operational verification reference was not measured")
		}
		t.Run(view.target.String(), func(t *testing.T) {
			extraSite := operational
			extraSite.site = "es/admission/reliable_submit_operational_format.go:unreviewedDirectCall"
			escape := operational
			escape.directCall = false
			closure := operational
			closure.insideFuncLiteral = true
			for _, tc := range []struct {
				name   string
				ref    typedReference
				reason string
			}{
				{"UnlistedDirectSite", extraSite, "reference inventory changed"},
				{"ExtraDirectOccurrence", operational, "reference inventory changed"},
				{"OperationalFunctionValue", escape, "indirect reference escape"},
				{"OperationalClosure", closure, "indirect reference escape"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					changed := append(append([]typedReference(nil), refs...), tc.ref)
					err := validateTypedReferenceInventory("private PB1 caller closure", changed, want, true)
					if err == nil || !strings.Contains(err.Error(), tc.reason) {
						t.Fatalf("expected the typed guard to reject %s: %v", tc.name, err)
					}
				})
			}
		})
	}
	for _, rel := range []string{"es/admission/submit.go", "es/api/server.go", "es/app/app.go", "es/config/config.go"} {
		source := mustReadAdmissionRepoSource(t, admissionRepoRoot(t), rel)
		if strings.Contains(source, "admitPrivateSyntheticReplay") || strings.Contains(source, "OpenPrivateReplayCustody") {
			t.Fatalf("runtime file %s calls private replay", rel)
		}
	}
	privateSource := mustReadAdmissionSource(t, "reliable_submit_replay_private.go")
	mutant := strings.Replace(privateSource, "assessment, err := buildReliableSubmitAdmissionBinding(resolved, delivery.family, keys.binding)", "builder := buildReliableSubmitAdmissionBinding\n\tassessment, err := builder(resolved, delivery.family, keys.binding)", 1)
	if mutant == privateSource {
		t.Fatal("private caller mutation anchor missing")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "es/admission/reliable_submit_replay_private.go", mutant, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindingValidateOtherProductionSource("es/admission/reliable_submit_replay_private.go", file); err == nil {
		t.Fatal("function-value escape passed private guard")
	}

	const operationalPath = "es/admission/reliable_submit_operational_format.go"
	operational := mustReadAdmissionSource(t, "reliable_submit_operational_format.go")
	const direct = "assessment, err := buildReliableSubmitAdmissionBinding(resolved, family, keys.key)"
	const escaped = "builder := buildReliableSubmitAdmissionBinding\n\tassessment, err := builder(resolved, family, keys.key)"
	mutant = strings.Replace(operational, direct, escaped, 1)
	if mutant == operational {
		t.Fatal("operational caller mutation anchor missing")
	}
	file, err = parser.ParseFile(token.NewFileSet(), operationalPath, mutant, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindingValidateOtherProductionSource(operationalPath, file); err == nil ||
		!strings.Contains(err.Error(), "references private binding producer buildReliableSubmitAdmissionBinding") {
		t.Fatalf("operational function-value escape did not reach the binding guard: %v", err)
	}
}

func privateBindingCallerInventory() map[string]int {
	return map[string]int{
		"es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay":   1,
		"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal":           1,
		"es/admission/reliable_submit_operational_handoff.go:Service.composeOperationalOriginal": 1,
		"es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal":           1,
	}
}

func TestPrivateReplayProgressAdmissionReplay(t *testing.T) {
	t.Run("RetainedOriginalAfterRestartAndDrift", func(t *testing.T) {
		ctx := context.Background()
		service, raw, caller, keys, image := privateReplayServiceFixture(t)
		root := privateReplayTestRoot(t)
		open := func() *reliablesubmit.PrivateReplayProgressCustody {
			c, err := reliablesubmit.OpenPrivateReplayProgressCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		c := open()
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		state, p, err := service.admitPrivateProgressReplay(ctx, c, raw, caller, catalog, image, reliablesubmit.FixtureAmbiguousBeforeAssignment)
		if err != nil || state != reliablesubmit.FixtureProgressCommitted || p.Revision() != 1 || p.Phase() != reliablesubmit.FixtureAmbiguousBeforeAssignment {
			t.Fatalf("establish: state=%d revision=%d phase=%d err=%v", state, p.Revision(), p.Phase(), err)
		}
		run := reliablesubmit.NewFixtureRunRef([32]byte{1})
		state, p, err = service.applyPrivateProgressReplay(ctx, c, raw, caller, catalog, 1,
			reliablesubmit.NewFixtureMutationRef([32]byte{2}), reliablesubmit.FixtureAssignRun{Run: run})
		if err != nil || state != reliablesubmit.FixtureProgressCommitted || p.Revision() != 2 {
			t.Fatalf("assign: state=%d revision=%d err=%v", state, p.Revision(), err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		c = open()
		active, err := newPrivateSyntheticKeyBundle("Binding-New", bytes.Repeat([]byte{0x61}, 32), "Envelope-New", bytes.Repeat([]byte{0x62}, 32))
		if err != nil {
			t.Fatal(err)
		}
		drifted, err := newPrivateSyntheticKeyCatalog(active, keys)
		if err != nil {
			t.Fatal(err)
		}
		inertService := &Service{}
		before, err := os.ReadDir(filepath.Join(root, "objects", "v1"))
		if err != nil || len(before) != 1 {
			t.Fatalf("before: objects=%d err=%v", len(before), err)
		}
		state, p, err = inertService.admitPrivateProgressReplay(ctx, c, raw, caller, drifted, privateSyntheticImagePlacement{}, 0)
		sameRun, hasRun := p.Run()
		if err != nil || state != reliablesubmit.FixtureProgressCurrent || p.Revision() != 2 || !hasRun || !sameRun.Equal(run) {
			t.Fatalf("current: state=%d revision=%d err=%v", state, p.Revision(), err)
		}
		var request map[string]any
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		request["invocation"].(map[string]any)["argv"] = []string{"changed"}
		changed, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		state, p, err = inertService.admitPrivateProgressReplay(ctx, c, changed, caller, drifted, privateSyntheticImagePlacement{}, 0)
		if !errors.Is(err, errPrivateReplayConflict) || state != reliablesubmit.FixtureProgressConflict || p.Revision() != 0 {
			t.Fatalf("conflict: state=%d revision=%d err=%v", state, p.Revision(), err)
		}
		missing, err := newPrivateSyntheticKeyCatalog(active)
		if err != nil {
			t.Fatal(err)
		}
		state, p, err = inertService.admitPrivateProgressReplay(ctx, c, raw, caller, missing, privateSyntheticImagePlacement{}, 0)
		if !errors.Is(err, errPrivateReplayUnavailable) || state != reliablesubmit.FixtureProgressRefused || p.Revision() != 0 {
			t.Fatalf("missing original: state=%d revision=%d err=%v", state, p.Revision(), err)
		}
		after, err := os.ReadDir(filepath.Join(root, "objects", "v1"))
		if err != nil || len(after) != 1 || before[0].Name() != after[0].Name() {
			t.Fatalf("occupied replay changed objects: %v", err)
		}
	})
	t.Run("ScopeOneOccupiesSameKey", func(t *testing.T) {
		ctx := context.Background()
		service, raw, caller, keys, image := privateReplayServiceFixture(t)
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		old, root := openPrivateReplayTestCustody(t)
		defer old.Close()
		if _, err := service.admitPrivateSyntheticReplay(ctx, old, raw, caller, catalog, image); err != nil {
			t.Fatal(err)
		}
		progress, err := reliablesubmit.OpenPrivateReplayProgressCustody(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		defer progress.Close()
		state, p, err := (&Service{}).admitPrivateProgressReplay(ctx, progress, raw, caller, catalog, privateSyntheticImagePlacement{}, 0)
		if !errors.Is(err, errPrivateReplayUnavailable) || state != reliablesubmit.FixtureProgressRefused || p.Revision() != 0 {
			t.Fatalf("opposite scope: state=%d revision=%d err=%v", state, p.Revision(), err)
		}
	})
	t.Run("ConcurrentInitialWinner", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		service, raw, caller, keys, image := privateReplayServiceFixture(t)
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		root := privateReplayTestRoot(t)
		custodies := make([]*reliablesubmit.PrivateReplayProgressCustody, 2)
		for i := range custodies {
			custodies[i], err = reliablesubmit.OpenPrivateReplayProgressCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer custodies[i].Close()
		}
		arrived, release := make(chan struct{}, 2), make(chan struct{})
		beforePrivateReplayClaimForTest = func() { arrived <- struct{}{}; <-release }
		type result struct {
			state reliablesubmit.FixtureProgressDisposition
			view  reliablesubmit.FixtureProgress
			error error
		}
		results := make(chan result, len(custodies))
		var workers sync.WaitGroup
		defer func() {
			workers.Wait()
			beforePrivateReplayClaimForTest = nil
		}()
		for _, c := range custodies {
			workers.Add(1)
			go func() {
				defer workers.Done()
				state, view, err := service.admitPrivateProgressReplay(ctx, c, raw, caller, catalog, image, reliablesubmit.FixturePendingBeforeAssignment)
				results <- result{state, view, err}
			}()
		}
		reached := 0
		for reached < len(custodies) && ctx.Err() == nil {
			select {
			case <-arrived:
				reached++
			case <-ctx.Done():
			}
		}
		close(release)
		if reached != len(custodies) {
			t.Fatal("both contenders must publish before establishment")
		}
		counts := make(map[reliablesubmit.FixtureProgressDisposition]int)
		for range custodies {
			out := <-results
			if out.error != nil || out.view.Revision() != 1 {
				t.Fatalf("concurrent result: %d %d %v", out.state, out.view.Revision(), out.error)
			}
			counts[out.state]++
		}
		if counts[reliablesubmit.FixtureProgressCommitted] != 1 || counts[reliablesubmit.FixtureProgressOccupied] != 1 {
			t.Fatalf("initial winner classification: %v", counts)
		}
	})
	t.Run("OccupiedAtCapacityAndValidMissRefusal", func(t *testing.T) {
		ctx := context.Background()
		service, raw, caller, keys, image := privateReplayServiceFixture(t)
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		c, err := reliablesubmit.OpenPrivateReplayProgressCustody(ctx, privateReplayTestRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var request map[string]any
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 5; i++ {
			request["reliable_submit"].(map[string]any)["submit_key"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i)}, 32))
			input, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			state, p, err := service.admitPrivateProgressReplay(ctx, c, input, caller, catalog, image, reliablesubmit.FixturePendingBeforeAssignment)
			if i == 5 {
				if err == nil || state != reliablesubmit.FixtureProgressRefused || p.Revision() != 0 {
					t.Fatalf("fifth claim exceeded capacity: %d %d %v", state, p.Revision(), err)
				}
				continue
			}
			if err != nil || state != reliablesubmit.FixtureProgressCommitted || p.Revision() != 1 {
				t.Fatalf("claim %d: %d %d %v", i, state, p.Revision(), err)
			}
			if i == 1 {
				raw = input
			}
		}
		state, p, err := (&Service{}).admitPrivateProgressReplay(ctx, c, raw, caller, catalog, privateSyntheticImagePlacement{}, 0)
		if err != nil || state != reliablesubmit.FixtureProgressCurrent || p.Revision() != 1 {
			t.Fatalf("existing claim at capacity: %d %d %v", state, p.Revision(), err)
		}
	})
}

func TestPrivateReplayProgressHasNoEffectPaths(t *testing.T) {
	assertPrivateReplayProgressCallers(t)
	ctx := context.Background()
	s, raw, caller, keys, image := privateReplayServiceFixture(t)
	var providerCalls, stagingCalls, liveDependencyCalls atomic.Int64
	s.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	s.egsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		liveDependencyCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	beforeStagingChildRegistrationStatForTest = func(string, int, bool) { stagingCalls.Add(1) }
	beforeStagingHandoffValidationForTest = func(*stagingCustody) { stagingCalls.Add(1) }
	defer func() {
		beforeStagingChildRegistrationStatForTest = nil
		beforeStagingHandoffValidationForTest = nil
	}()
	catalog, err := newPrivateSyntheticKeyCatalog(keys)
	if err != nil {
		t.Fatal(err)
	}
	root := privateReplayTestRoot(t)
	c, err := reliablesubmit.OpenPrivateReplayProgressCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, p, err := s.admitPrivateProgressReplay(ctx, c, raw, caller, catalog, image, reliablesubmit.FixturePendingBeforeAssignment)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	run := reliablesubmit.NewFixtureRunRef([32]byte{1})
	marker := reliablesubmit.NewFixtureFactRef([32]byte{2})
	receipt := reliablesubmit.NewFixtureReceiptRef([32]byte{3})
	accepted, err := reliablesubmit.NewFixtureAcceptedEvidence(delivery.refs.claimID, run, marker,
		reliablesubmit.NewFixtureFactRef([32]byte{6}), receipt)
	if err != nil {
		t.Fatal(err)
	}
	for i, command := range []reliablesubmit.FixtureProgressCommand{
		reliablesubmit.FixtureAssignRun{Run: run},
		reliablesubmit.FixtureRecordIntent{Fact: reliablesubmit.NewFixtureFactRef([32]byte{4})},
		reliablesubmit.FixtureRecordStaging{Fact: reliablesubmit.NewFixtureFactRef([32]byte{5})},
		reliablesubmit.FixtureRecordMarker{Run: run, Marker: marker},
		reliablesubmit.FixtureAccept{Evidence: accepted, Receipt: receipt},
	} {
		var state reliablesubmit.FixtureProgressDisposition
		state, p, err = s.applyPrivateProgressReplay(ctx, c, raw, caller, catalog, p.Revision(),
			reliablesubmit.NewFixtureMutationRef([32]byte{byte(i + 10)}), command)
		if err != nil || state != reliablesubmit.FixtureProgressCommitted || p.Revision() != int64(i+2) {
			t.Fatalf("fixture step %d: state=%d revision=%d err=%v", i, state, p.Revision(), err)
		}
	}
	gotReceipt, ok := p.Receipt()
	if p.Phase() != reliablesubmit.FixtureAccepted || !ok || !gotReceipt.Equal(receipt) {
		t.Fatal("fixture terminal projection lost its receipt")
	}
	if _, operational := any(gotReceipt).(reliablesubmit.ReceiptRef); operational {
		t.Fatal("fixture projected an operational receipt")
	}
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	request["invocation"].(map[string]any)["argv"] = []string{"changed original"}
	changed, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	state, projected, err := s.admitPrivateProgressReplay(ctx, c, changed, caller, catalog, image, reliablesubmit.FixturePendingBeforeAssignment)
	if state != reliablesubmit.FixtureProgressConflict || !errors.Is(err, errPrivateReplayConflict) || projected.Revision() != 0 {
		t.Fatal("changed original disclosed terminal progress")
	}
	incompatible, err := reliablesubmit.OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer incompatible.Close()
	if _, err := s.admitPrivateSyntheticReplay(ctx, incompatible, raw, caller, catalog, image); !errors.Is(err, errPrivateReplayUnavailable) {
		t.Fatalf("incompatible scope entered the old selector: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	state, p, err = s.admitPrivateProgressReplay(canceled, c, raw, caller, catalog, image, reliablesubmit.FixturePendingBeforeAssignment)
	if err == nil || state != reliablesubmit.FixtureProgressRefused || p.Revision() != 0 {
		t.Fatal("canceled entry disclosed progress")
	}
	if providerCalls.Load() != 0 || stagingCalls.Load() != 0 || liveDependencyCalls.Load() != 0 {
		t.Fatalf("fixture crossed an effect boundary: provider=%d staging=%d live=%d", providerCalls.Load(), stagingCalls.Load(), liveDependencyCalls.Load())
	}
	for _, effectRoot := range []string{s.cfg.Execution.StagingRootDir, s.cfg.Execution.ResultsRootDir} {
		entries, err := os.ReadDir(effectRoot)
		if err != nil || len(entries) != 0 {
			t.Fatalf("fixture touched an operational root: %v", err)
		}
	}
}

func TestPrivateReplayProgressOccupiedDisposition(t *testing.T) {
	for _, trial := range []string{"DisjointCatalog", "EquivalentWinner", "ChangedIntent", "UnavailableWinner"} {
		t.Run(trial, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
			defer stop()
			service, raw, caller, firstKey, image := privateReplayServiceFixture(t)
			secondKey, err := newPrivateSyntheticKeyBundle("Binding-Loser", bytes.Repeat([]byte{0x61}, 32),
				"Envelope-Loser", bytes.Repeat([]byte{0x62}, 32))
			if err != nil {
				t.Fatal(err)
			}
			first, err := newPrivateSyntheticKeyCatalog(firstKey)
			if err != nil {
				t.Fatal(err)
			}
			var retained []privateSyntheticKeyBundle
			if trial != "DisjointCatalog" {
				retained = append(retained, firstKey)
			}
			second, err := newPrivateSyntheticKeyCatalog(secondKey, retained...)
			if err != nil {
				t.Fatal(err)
			}
			loserRaw := raw
			if trial == "ChangedIntent" {
				var request map[string]any
				if err := json.Unmarshal(raw, &request); err != nil {
					t.Fatal(err)
				}
				request["invocation"].(map[string]any)["argv"] = []string{"changed fixture"}
				loserRaw, err = json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
			}
			root := privateReplayTestRoot(t)
			open := func() *reliablesubmit.PrivateReplayProgressCustody {
				t.Helper()
				c, err := reliablesubmit.OpenPrivateReplayProgressCustody(ctx, root)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			winner, loser := open(), open()
			objectDir := filepath.Join(root, "objects", "v1")
			objects := func() map[string][32]byte {
				t.Helper()
				entries, err := os.ReadDir(objectDir)
				if err != nil {
					t.Fatal(err)
				}
				got := make(map[string][32]byte, len(entries))
				for _, entry := range entries {
					b, err := os.ReadFile(filepath.Join(objectDir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					got[entry.Name()] = sha256.Sum256(b)
				}
				return got
			}
			arrived := make(chan chan struct{}, 2)
			var edgeCount atomic.Int64
			beforePrivateReplayClaimForTest = func() {
				edgeCount.Add(1)
				gate := make(chan struct{})
				select {
				case arrived <- gate:
				case <-ctx.Done():
					return
				}
				select {
				case <-gate:
				case <-ctx.Done():
				}
			}
			var workers sync.WaitGroup
			defer func() {
				stop()
				workers.Wait()
				beforePrivateReplayClaimForTest = nil
			}()
			type outcome struct {
				state reliablesubmit.FixtureProgressDisposition
				p     reliablesubmit.FixtureProgress
				err   error
			}
			start := func(c *reliablesubmit.PrivateReplayProgressCustody, request []byte, keys privateSyntheticKeyCatalog) <-chan outcome {
				result := make(chan outcome, 1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					state, p, err := service.admitPrivateProgressReplay(ctx, c, request, caller, keys, image,
						reliablesubmit.FixturePendingBeforeAssignment)
					result <- outcome{state, p, err}
				}()
				return result
			}
			awaitPublication := func() chan struct{} {
				t.Helper()
				select {
				case gate := <-arrived:
					return gate
				case <-ctx.Done():
					t.Fatal("initial contender did not reach the post-publication barrier")
					return nil
				}
			}
			won := start(winner, raw, first)
			firstGate := awaitPublication()
			winnerObjects := objects()
			if len(winnerObjects) != 1 {
				t.Fatal("winner did not publish exactly one object")
			}
			lost := start(loser, loserRaw, second)
			secondGate := awaitPublication()
			before := objects()
			if len(before) != 2 {
				t.Fatal("both initial proposals must seal before the first establishment")
			}
			close(firstGate)
			if out := <-won; out.state != reliablesubmit.FixtureProgressCommitted || out.p.Revision() != 1 || out.err != nil {
				t.Fatalf("controlled first writer did not win: %d %d %v", out.state, out.p.Revision(), out.err)
			}
			if trial == "UnavailableWinner" {
				for name := range winnerObjects {
					path := filepath.Join(objectDir, name)
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
					defer os.Chmod(path, 0o600)
				}
			}
			close(secondGate)
			out := <-lost
			wantState, wantRevision, wantErr := reliablesubmit.FixtureProgressOccupied, int64(0), errPrivateReplayUnavailable
			switch trial {
			case "EquivalentWinner":
				wantRevision, wantErr = 1, nil
			case "ChangedIntent":
				wantState, wantErr = reliablesubmit.FixtureProgressConflict, errPrivateReplayConflict
			case "UnavailableWinner":
				for name := range winnerObjects {
					if err := os.Chmod(filepath.Join(objectDir, name), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if out.state != wantState || out.p.Revision() != wantRevision || !errors.Is(out.err, wantErr) {
				t.Errorf("loser outcome: disposition=%d revision=%d err=%v", out.state, out.p.Revision(), out.err)
			}
			if _, hasRun := out.p.Run(); hasRun {
				t.Error("loser disclosed an unassigned run")
			}
			if _, hasReceipt := out.p.Receipt(); hasReceipt {
				t.Error("loser disclosed a receipt")
			}
			state, current, err := (&Service{}).admitPrivateProgressReplay(ctx, winner, raw, caller, first, privateSyntheticImagePlacement{}, 0)
			if err != nil || state != reliablesubmit.FixtureProgressCurrent || current.Revision() != 1 {
				t.Fatalf("winner changed or lost its original: %d %d %v", state, current.Revision(), err)
			}
			if !maps.Equal(before, objects()) || edgeCount.Load() != 2 {
				t.Fatal("winner disclosure retried or changed the winner or losing sealed orphan")
			}
			t.Log("two legitimate seals, one established revision, both objects preserved after disclosure")
		})
	}
}
