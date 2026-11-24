package admission

// Red-team regression tests for PR #12 at 4416699 (report 28-redteam.md):
// crashes and contention across processes and on the writer lock of the store.
// They go beyond TestRedTeamPR12CombinedSIGKILLAtRandomInstants (one kill of
// one process) and the two-process test with a chosen winner: a second kill
// lands in the recovery of the first, several live processes race for one
// claim with nothing ordering them, and a foreign connection takes the writer
// lock while a delivery runs.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// redTeam3KillWindow is the span after the barrier in which a child is
// killed: lower bound and width in milliseconds (ES_RT_KILL_WINDOW_MS, as in
// the adopted SIGKILL test).
func redTeam3KillWindow(t *testing.T) (int, int) {
	t.Helper()
	low, span := 0, 70
	if v := os.Getenv("ES_RT_KILL_WINDOW_MS"); v != "" {
		if _, err := fmt.Sscan(v, &low, &span); err != nil || span <= 0 {
			t.Fatalf("ES_RT_KILL_WINDOW_MS=%q", v)
		}
	}
	return low, span
}

// redTeam3ChildPath writes the fixture of a child that reports its result
// without asserting one. The sentinel's hold before the pre-stage turn is
// answered in advance, so the child never waits there.
func redTeam3ChildPath(t *testing.T, f *operationalFixture) string {
	t.Helper()
	fixture := f.childFixture()
	fixture.HoldBeforePrestage = true
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "child.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// redTeam3Child is one started child that waits at its barrier.
type redTeam3Child struct {
	operationalChild
	kill context.CancelFunc
}

func redTeam3StartChild(t *testing.T, path string) redTeam3Child {
	t.Helper()
	ctx, kill := context.WithCancel(context.Background())
	t.Cleanup(kill)
	child := startOperationalChild(t, ctx, path)
	select {
	case <-child.ready:
	case logs := <-child.result:
		t.Fatalf("child stopped before readiness:\n%s", logs)
	case <-time.After(60 * time.Second):
		t.Fatal("child readiness timeout")
	}
	return redTeam3Child{operationalChild: child, kill: kill}
}

// release lets the child pass its barrier and, in advance, the hold before
// the pre-stage turn.
func (c redTeam3Child) release(t *testing.T) {
	t.Helper()
	if _, err := fmt.Fprint(c.input, "go\ngo\n"); err != nil {
		t.Fatal(err)
	}
}

// wait returns the kind the child reported, or -1 when it died first.
func (c redTeam3Child) wait(t *testing.T) int {
	t.Helper()
	select {
	case logs := <-c.result:
		for _, line := range strings.Split(logs, "\n") {
			if rest, ok := strings.CutPrefix(line, "ES_OPERATIONAL_CHILD_HELD_RESULT "); ok {
				var kind int
				if _, err := fmt.Sscan(rest, &kind); err != nil {
					t.Fatal(err)
				}
				return kind
			}
		}
		if os.Getenv("ES_RT_KILL_LOGS") != "" {
			t.Logf("child logs:\n%s", logs)
		}
		return -1
	case <-time.After(120 * time.Second):
		t.Fatal("child did not end")
		return -1
	}
}

// redTeam3Durable checks what holds after any crash or race: the store opens
// and is sound, one claim exists, nothing was sent twice, and the claim never
// moved backwards.
func redTeam3Durable(t *testing.T, f *operationalFixture, before operationalPrestageState, what string) operationalPrestageState {
	t.Helper()
	var integrity string
	if err := f.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("%s: integrity: %q %v", what, integrity, err)
	}
	state := operationalPrestageStateAt(t, f)
	if state.Posts > 1 || state.Claims != 1 || state.Revision < before.Revision || state.RowID != before.RowID ||
		before.Marker && !state.Marker || before.Receipt && !state.Receipt || state.Receipt && state.Posts != 1 {
		t.Fatalf("%s: before=%+v after=%+v", what, before, state)
	}
	return state
}

// redTeam3Survivor lets the fixture's own Service, a live process of the same
// generation, take the claim after the others ended, and names the end state.
// Every end state other than completion is one the owner document accepts
// after a crash: charged stage residue, or a marker without its sender.
func redTeam3Survivor(t *testing.T, f *operationalFixture, before operationalPrestageState, what string) string {
	t.Helper()
	ctx := context.Background()
	out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
	after := redTeam3Durable(t, f, before, what+": survivor")
	switch {
	case out.kind == operationalAccepted:
		if after.Posts != 1 || !after.Receipt || after.Revision != 6 {
			t.Fatalf("%s: accepted without exactly one POST and the receipt: %+v", what, after)
		}
		return "completed"
	case after.Posts == 0 && after.Marker:
		return "marker without sender"
	case after.Posts == 0 && (after.Stamp || after.StageEntries > 0):
		return "stage residue"
	case after.Posts == 1:
		again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		redTeam3Durable(t, f, after, what+": second survivor call")
		return fmt.Sprintf("sent by a dead process, then kind %d", again.kind)
	default:
		t.Fatalf("%s: unexpected end state: out=%s before=%+v after=%+v", what, operationalResultText(out), before, after)
		return ""
	}
}

// redTeam3Checkpoints truncates the write-ahead log from a foreign connection
// until the returned function is called.
func redTeam3Checkpoints(f *operationalFixture, enabled bool) func() {
	if !enabled {
		return func() {}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A busy answer is expected and ignored: the point is the attempt.
			_, _ = f.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
			time.Sleep(200 * time.Microsecond)
		}
	}()
	return func() { close(stop); <-done }
}

// Two processes in a row take a retained claim and each is killed with
// SIGKILL at a random instant, so the second kill can land in the recovery of
// what the first left. In half of the rounds a foreign connection truncates
// the write-ahead log throughout. Whatever the two instants are, the store
// stays sound, the claim never moves backwards, nothing is sent twice, and
// the surviving process completes the claim with exactly one POST or leaves it
// in a documented stopped state without a second POST.
func TestRedTeamPR12HeadTwoSIGKILLsThenASurvivor(t *testing.T) {
	random := rand.New(rand.NewSource(redTeam3Seed(t)))
	low, span := redTeam3KillWindow(t)
	outcomes := map[string]int{}
	for round, rounds := 0, redTeam3Rounds(t, 16); round < rounds; round++ {
		delays := []time.Duration{time.Duration(low+random.Intn(span)) * time.Millisecond,
			time.Duration(low+random.Intn(span)) * time.Millisecond}
		checkpoints := round%2 == 1
		t.Run(fmt.Sprintf("round %d after %v and %v checkpoints %t", round, delays[0], delays[1], checkpoints), func(t *testing.T) {
			f, _, state := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
			path := redTeam3ChildPath(t, f)
			stop := redTeam3Checkpoints(f, checkpoints)
			trace := ""
			for i, delay := range delays {
				child := redTeam3StartChild(t, path)
				child.release(t)
				time.Sleep(delay)
				child.kill() // exec.CommandContext sends SIGKILL
				kind := child.wait(t)
				state = redTeam3Durable(t, f, state, fmt.Sprintf("after kill %d", i+1))
				trace += fmt.Sprintf("kill %d: child kind %d, revision %d, posts %d; ", i+1, kind, state.Revision, state.Posts)
			}
			stop()
			outcome := redTeam3Survivor(t, f, state, "two kills")
			outcomes[outcome]++
			t.Logf("%s outcome=%s", trace, outcome)
		})
	}
	t.Logf("outcomes: %v", outcomes)
}

// Three child processes and the parent take one retained claim at the same
// moment, with nothing ordering them. In every third round one child is
// killed at a random instant. Nothing is sent twice. When no process is
// killed the claim is not lost: after the race one more delivery ends with
// exactly one POST and the receipt.
func TestRedTeamPR12HeadLiveProcessesRaceForOneClaim(t *testing.T) {
	random := rand.New(rand.NewSource(redTeam3Seed(t)))
	low, span := redTeam3KillWindow(t)
	outcomes := map[string]int{}
	for round, rounds := 0, redTeam3Rounds(t, 12); round < rounds; round++ {
		victim, delay := -1, time.Duration(0)
		if round%3 == 2 {
			victim, delay = random.Intn(3), time.Duration(low+random.Intn(span))*time.Millisecond
		}
		// The name carries no '=': it becomes part of the staging path, and the
		// custody rules refuse such a path.
		t.Run(fmt.Sprintf("round %d victim %d after %v", round, victim, delay), func(t *testing.T) {
			ctx := context.Background()
			f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
			path := redTeam3ChildPath(t, f)
			children := []redTeam3Child{redTeam3StartChild(t, path), redTeam3StartChild(t, path), redTeam3StartChild(t, path)}
			own := f.reopen()
			parent := make(chan operationalHandoffResult, 1)
			for _, child := range children {
				child.release(t)
			}
			go func() { parent <- f.service.handoffOperational(ctx, own, f.domain.caller, f.raw) }()
			if victim >= 0 {
				time.Sleep(delay)
				children[victim].kill()
			}
			accepted, kinds := 0, ""
			for _, child := range children {
				kind := child.wait(t)
				kinds += fmt.Sprintf("%d ", kind)
				if kind == int(operationalAccepted) {
					accepted++
				}
			}
			var out operationalHandoffResult
			select {
			case out = <-parent:
			case <-time.After(120 * time.Second):
				t.Fatal("the parent's delivery did not end")
			}
			if out.kind == operationalAccepted {
				accepted++
			}
			raced := redTeam3Durable(t, f, seeded, "after the race")
			if accepted > 0 && (raced.Posts != 1 || !raced.Receipt) {
				t.Fatalf("accepted without the one POST and its receipt: children=%sparent=%d state=%+v", kinds, out.kind, raced)
			}
			outcome := redTeam3Survivor(t, f, raced, "after the race")
			if victim < 0 && outcome != "completed" {
				t.Fatalf("no process was killed and the claim was lost: children=%sparent=%d raced=%+v outcome=%s",
					kinds, out.kind, raced, outcome)
			}
			outcomes[fmt.Sprintf("killed=%t %s", victim >= 0, outcome)]++
			t.Logf("children=%sparent=%d accepted=%d raced=%+v outcome=%s", kinds, out.kind, accepted, raced, outcome)
		})
	}
	t.Logf("outcomes: %v", outcomes)
}

// A foreign connection takes the writer lock of the store again and again for
// a few milliseconds, far below the busy timeout of five seconds, and
// truncates the write-ahead log in between, while a fresh delivery runs.
// Short contention neither strands the claim nor repeats an effect: the
// delivery completes with exactly one POST and the receipt.
func TestRedTeamPR12HeadShortWriterLockContentionDoesNotStrandAClaim(t *testing.T) {
	seed := redTeam3Seed(t)
	for round, rounds := 0, redTeam3Rounds(t, 16); round < rounds; round++ {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			ctx := context.Background()
			f := makeOperationalFixture(t, "")
			d := f.reopen()
			conn, err := f.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var holds int
			wg.Add(1)
			go func() {
				defer wg.Done()
				random := rand.New(rand.NewSource(seed + int64(round)))
				for {
					select {
					case <-stop:
						return
					default:
					}
					// A busy answer means the delivery holds the lock: try again.
					if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err == nil {
						holds++
						time.Sleep(time.Duration(random.Intn(8000)) * time.Microsecond)
						_, _ = conn.ExecContext(ctx, "ROLLBACK")
					}
					if random.Intn(3) == 0 {
						_, _ = conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
					}
					time.Sleep(time.Duration(random.Intn(8000)) * time.Microsecond)
				}
			}()
			started := time.Now()
			out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
			elapsed := time.Since(started)
			close(stop)
			wg.Wait()
			state := operationalPrestageStateAt(t, f)
			if state.Posts > 1 || state.Claims > 1 {
				t.Fatalf("contention repeated an effect: %+v", state)
			}
			if out.kind != operationalAccepted || state.Posts != 1 || !state.Receipt || state.Revision != 6 {
				t.Fatalf("writer-lock holds of at most 8ms (%d of them in %v) stopped the delivery: %s state=%+v",
					holds, elapsed, operationalResultText(out), state)
			}
			t.Logf("%d foreign holds in %v", holds, elapsed)
		})
	}
}
