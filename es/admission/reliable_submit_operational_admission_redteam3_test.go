package admission

// Red-team regression tests for PR #12 at 4416699 (report 28-redteam.md).
// They attack beyond the adopted tests of 13-red-team.md: a withdrawal or an
// advance that another Service commits at an instant chosen at random while a
// handoff is running, instead of at one synchronous hook. Each test passes
// when the property holds and fails if a later change reopens the road.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// redTeam3Rounds returns the number of randomized rounds: the given number,
// a quarter of it with -short, or ES_RT3_ROUNDS when that is set.
func redTeam3Rounds(t *testing.T, normal int) int {
	t.Helper()
	rounds := normal
	if testing.Short() {
		rounds = max(normal/4, 2)
	}
	if v := os.Getenv("ES_RT3_ROUNDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("ES_RT3_ROUNDS=%q", v)
		}
		rounds = n
	}
	return rounds
}

func redTeam3Seed(t *testing.T) int64 {
	t.Helper()
	seed := time.Now().UnixNano()
	if v := os.Getenv("ES_RT3_SEED"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("ES_RT3_SEED=%q", v)
		}
		seed = n
	}
	t.Logf("seed %d (set ES_RT3_SEED to repeat)", seed)
	return seed
}

// redTeam3Snapshot is one consistent read of the claim table, taken without
// the testing.T so that a racing goroutine can take it.
type redTeam3Snapshot struct {
	Claims, Revision int
	Marker, Receipt  bool
}

func redTeam3SnapshotAt(f *operationalFixture) (redTeam3Snapshot, error) {
	var s redTeam3Snapshot
	var marker, receipt int
	err := f.db.QueryRow(`SELECT count(*), coalesce(max(revision),0), coalesce(max(dispatch_ref IS NOT NULL),0),
coalesce(max(receipt_ref IS NOT NULL),0) FROM reliable_submit_claims`).Scan(&s.Claims, &s.Revision, &marker, &receipt)
	s.Marker, s.Receipt = marker != 0, receipt != 0
	return s, err
}

// redTeam3Triggers are the points of a running handoff at which the racing
// goroutine is released. It is released, not awaited: the handoff goes on
// while the other Service writes.
var redTeam3Triggers = []string{"timer", "beforeEstablish", "afterEstablish", "beforePrestage", "beforeStageCreate",
	"beforeMaterialize", "beforeStamp", "beforeMarker", "beforeConsume", "beforeEntrySample",
	"release assign", "release intent", "release stamp", "release mark"}

// redTeam3Arm makes the named point of a handoff on d call fire, once.
func redTeam3Arm(t *testing.T, d *operationalDomain, trigger string, fire func()) {
	t.Helper()
	var once sync.Once
	hit := func() { once.Do(fire) }
	hooks := &operationalHandoffProofHooks{}
	switch trigger {
	case "timer":
		hit()
	case "beforeEstablish":
		hooks.beforeEstablish = hit
	case "afterEstablish":
		hooks.afterEstablish = hit
	case "beforePrestage":
		hooks.beforePrestage = hit
	case "beforeStageCreate":
		hooks.beforeStageCreate = hit
	case "beforeMaterialize":
		hooks.beforeMaterialize = hit
	case "beforeStamp":
		hooks.beforeStamp = hit
	case "beforeMarker":
		hooks.beforeMarker = hit
	case "beforeConsume":
		hooks.beforeConsume = func(*liveSender, *handoffOwner) { hit() }
	case "beforeEntrySample":
		hooks.beforeEntrySample = hit
	case "release assign", "release intent", "release stamp", "release mark":
		want := map[string]reliablesubmit.OperationalOperation{"release assign": reliablesubmit.OperationalAssign,
			"release intent": reliablesubmit.OperationalIntent, "release stamp": reliablesubmit.OperationalStamp,
			"release mark": reliablesubmit.OperationalMark}[trigger]
		if err := d.custody.ConfigureOperationalReleaseProofForProof(func(op reliablesubmit.OperationalOperation) {
			if op == want {
				hit()
			}
		}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown trigger %q", trigger)
	}
	d.proof = hooks
}

type redTeam3Change struct {
	done bool
	snap redTeam3Snapshot
	err  error
}

// redTeam3RaceChange runs one fresh handoff of the fixture's claim by the
// fixture's Service and, from a point chosen at random, lets change run on
// another goroutine. change reports whether the durable change is confirmed.
// It returns the handoff's result, what the racing goroutine read right
// after its change returned, and the final state.
func redTeam3RaceChange(t *testing.T, f *operationalFixture, random *rand.Rand, change func() bool) (operationalHandoffResult, redTeam3Change, operationalPrestageState, string) {
	t.Helper()
	trigger := redTeam3Triggers[random.Intn(len(redTeam3Triggers))]
	delay := time.Duration(random.Intn(3000)) * time.Microsecond
	if trigger == "timer" {
		delay = time.Duration(random.Intn(40000)) * time.Microsecond
	}
	d := f.reopen()
	start := make(chan struct{})
	changed := make(chan redTeam3Change, 1)
	go func() {
		<-start
		time.Sleep(delay)
		var c redTeam3Change
		c.done = change()
		c.snap, c.err = redTeam3SnapshotAt(f)
		changed <- c
	}()
	redTeam3Arm(t, d, trigger, func() { close(start) })
	out := f.service.handoffOperational(context.Background(), d, d.caller, f.raw)
	var c redTeam3Change
	select {
	case <-start:
		select {
		case c = <-changed:
		case <-time.After(60 * time.Second):
			t.Fatalf("%s: the racing change did not return", trigger)
		}
	default:
		// The handoff ended before it reached the point. Run the change now
		// so that the goroutine ends; it raced nothing.
		close(start)
		c = <-changed
		c.done = false
	}
	if c.err != nil {
		t.Fatalf("%s: snapshot after the change: %v", trigger, c.err)
	}
	var integrity string
	if err := f.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("%s: integrity: %q %v", trigger, integrity, err)
	}
	final := operationalPrestageStateAt(t, f)
	what := fmt.Sprintf("%s+%v", trigger, delay)
	if final.Posts > 1 || final.Claims > 1 {
		t.Fatalf("%s: more than one POST or claim: %+v", what, final)
	}
	if out.kind == operationalAccepted && (final.Posts != 1 || !final.Receipt || final.Revision != 6) {
		t.Fatalf("%s: accepted without exactly one POST and a receipt: %s final=%+v", what, operationalResultText(out), final)
	}
	if c.done {
		// A change that returned is committed. From then on the Service that
		// holds the old token commits no first-effect write: no claim, no run
		// assignment, no intent, no stamp, no marker. Only accept with receipt
		// of a marker that was already durable may follow.
		if final.Claims != c.snap.Claims {
			t.Fatalf("%s: a claim was established after the change returned: at return %+v final %+v", what, c.snap, final)
		}
		if final.Revision != c.snap.Revision && !(c.snap.Revision == 5 && final.Revision == 6) {
			t.Fatalf("%s: a first-effect write committed after the change returned: at return %+v final %+v out=%s",
				what, c.snap, final, operationalResultText(out))
		}
		if !c.snap.Marker && final.Posts != 0 {
			t.Fatalf("%s: a POST without a marker durable before the change returned: at return %+v final %+v", what, c.snap, final)
		}
	}
	return out, c, final, what
}

// A withdrawal committed by another Service of the same generation, or by the
// sending Service itself, at an instant chosen at random while a fresh
// delivery runs. Once the withdrawal has returned, no later first-effect
// write of the running handoff commits, and no POST is sent for a marker that
// was not durable by then (owner document, "A returned withdrawal therefore
// means that no later first-effect write commits on the domain").
func TestRedTeamPR12HeadWithdrawalAtRandomInstantsFencesARunningHandoff(t *testing.T) {
	random := rand.New(rand.NewSource(redTeam3Seed(t)))
	outcomes := map[string]int{}
	for round, rounds := 0, redTeam3Rounds(t, 24); round < rounds; round++ {
		own := round%2 == 1
		t.Run(fmt.Sprintf("round %d own %t", round, own), func(t *testing.T) {
			ctx := context.Background()
			f := makeOperationalFixture(t, "")
			withdrawer := f.service
			if !own {
				withdrawer = operationalProofService(t, f, nil)
			}
			dw := f.reopen()
			out, c, final, what := redTeam3RaceChange(t, f, random, func() bool {
				return withdrawer.withdrawOperationalEffects(ctx, dw)
			})
			if c.done {
				if row := operationalAdmissionRowAt(t, f); row.State != 2 {
					t.Fatalf("%s: confirmed withdrawal left the row %+v", what, row)
				}
				// The withdrawn domain stays stopped for a retry by either Service.
				again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				after := operationalPrestageStateAt(t, f)
				if after.Posts != final.Posts || after.Claims != final.Claims ||
					after.Revision != final.Revision && !(final.Revision == 5 && after.Revision == 6) {
					t.Fatalf("%s: a retry on the withdrawn domain acted: %s before=%+v after=%+v", what, operationalResultText(again), final, after)
				}
			}
			outcomes[fmt.Sprintf("raced=%t at-return=%d kind=%d final=%d posts=%d", c.done, c.snap.Revision, out.kind, final.Revision, final.Posts)]++
		})
	}
	t.Logf("outcomes: %v", outcomes)
}

// An advance to other content committed by a fresh Service at an instant
// chosen at random while a fresh delivery of the old generation runs. Once
// the advance has returned, the Service that holds the old token commits no
// further first-effect write and sends no POST for a marker that was not
// durable by then. A claim the old generation left before staging is
// completed by the new generation with exactly one POST.
func TestRedTeamPR12HeadAdvanceAtRandomInstantsFencesARunningHandoff(t *testing.T) {
	random := rand.New(rand.NewSource(redTeam3Seed(t)))
	outcomes := map[string]int{}
	for round, rounds := 0, redTeam3Rounds(t, 24); round < rounds; round++ {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			ctx := context.Background()
			f := makeOperationalFixture(t, "")
			next, _ := operationalUncommissionedService(t, f, operationalAllowingChange)
			da := f.reopen()
			out, c, final, what := redTeam3RaceChange(t, f, random, func() bool {
				return next.advanceOperationalAdmission(ctx, da, 1) == nil
			})
			outcomes[fmt.Sprintf("raced=%t at-return=%d kind=%d final=%d posts=%d", c.done, c.snap.Revision, out.kind, final.Revision, final.Posts)]++
			if !c.done {
				return
			}
			if row := operationalAdmissionRowAt(t, f); row.State != 1 || row.Generation != 2 {
				t.Fatalf("%s: row after the advance %+v", what, row)
			}
			// The fenced Service gains nothing by trying again.
			again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			after := operationalPrestageStateAt(t, f)
			if after.Posts != final.Posts || after.Claims != final.Claims ||
				after.Revision != final.Revision && !(final.Revision == 5 && after.Revision == 6) {
				t.Fatalf("%s: the fenced Service acted on a retry: %s before=%+v after=%+v", what, operationalResultText(again), final, after)
			}
			if after.Revision <= 3 && after.StageEntries == 0 {
				assertOperationalCompleted(t, f, next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw),
					what+": the new generation, before staging")
			}
		})
	}
	t.Logf("outcomes: %v", outcomes)
}
