package admission

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
	proposal, err := service.composePrivateSyntheticReplay(context.Background(), delivery, keys, image)
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
		arrived := make(chan struct{}, 2)
		release := make(chan struct{})
		beforePrivateReplayClaimForTest = func() { arrived <- struct{}{}; <-release }
		defer func() { beforePrivateReplayClaimForTest = nil }()
		type classified struct {
			kind privateReplayResultKind
			err  error
		}
		results := make(chan classified, 2)
		var workers sync.WaitGroup
		for i := 0; i < 2; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				result, err := service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, catalog, image)
				results <- classified{kind: result.kind, err: err}
			}()
		}
		<-arrived
		<-arrived
		close(release)
		workers.Wait()
		close(results)
		counts := map[privateReplayResultKind]int{}
		for result := range results {
			if result.err != nil {
				t.Fatalf("concurrent admission: %v", result.err)
			}
			counts[result.kind]++
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
		arrived := make(chan struct{}, 2)
		release := make(chan struct{})
		beforePrivateReplayClaimForTest = func() { arrived <- struct{}{}; <-release }
		defer func() { beforePrivateReplayClaimForTest = nil }()
		type classified struct {
			index  int
			result privateReplayResult
			err    error
		}
		results := make(chan classified, 2)
		var workers sync.WaitGroup
		for index, candidate := range []struct {
			service *Service
			catalog privateSyntheticKeyCatalog
			image   privateSyntheticImagePlacement
		}{
			{firstService, firstCatalog, firstImage},
			{secondService, secondCatalog, secondImage},
		} {
			workers.Add(1)
			go func() {
				defer workers.Done()
				result, err := candidate.service.admitPrivateSyntheticReplay(ctx, custody, raw, caller, candidate.catalog, candidate.image)
				results <- classified{index: index, result: result, err: err}
			}()
		}
		<-arrived
		<-arrived
		close(release)
		workers.Wait()
		close(results)
		var outcomes [2]classified
		for outcome := range results {
			if outcome.err != nil {
				t.Fatalf("drifted concurrent admission: %v", outcome.err)
			}
			outcomes[outcome.index] = outcome
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
	proposal, err := service.composePrivateSyntheticReplay(context.Background(), delivery, keys, image)
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
		if err := validateTypedReferenceInventory("private PB1 caller closure", pkg.referencesTo(requirePackageFunction(t, pkg, "buildReliableSubmitAdmissionBinding")), map[string]int{
			"es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1,
			"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal":         1,
		}, true); err != nil {
			t.Fatal(err)
		}
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
}
