package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

// Written by the red-team of the combined change of PR #12 and its fix PR #13
// (report 13-red-team.md, attack A-13) and adopted as a permanent test.
//
// A second process continues a retained claim through every writer to the
// POST and the receipt, and is killed
// with SIGKILL at a random instant. Whatever instant it dies at, the store
// opens again, its integrity check passes, the receiver saw at most one POST,
// and the surviving process of the same generation either completes the claim
// with exactly one POST or leaves it in one of the documented stopped states
// (charged stage residue, or a marker without its sender) without a POST.
// Nothing ever sends twice.
func TestRedTeamPR12CombinedSIGKILLAtRandomInstants(t *testing.T) {
	if os.Getenv("ES_OPERATIONAL_CHILD_FIXTURE") != "" {
		t.Skip("parent only")
	}
	rounds := 24
	if testing.Short() {
		rounds = 6
	}
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	random := rand.New(rand.NewSource(seed))
	// After the barrier the child needs some tens of milliseconds for the
	// whole handoff; the window spans it (calibrated on linux/amd64).
	low, span := 0, 60
	if v := os.Getenv("ES_RT_KILL_WINDOW_MS"); v != "" {
		if _, err := fmt.Sscan(v, &low, &span); err != nil {
			t.Fatal(err)
		}
	}
	outcomes := map[string]int{}
	for round := 0; round < rounds; round++ {
		delay := time.Duration(low+random.Intn(span)) * time.Millisecond
		t.Run(fmt.Sprintf("round %d after %v", round, delay), func(t *testing.T) {
			// The child has no resolver: it continues a retained claim from
			// its establishment to the POST and the receipt.
			f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
			raw, err := json.Marshal(f.childFixture())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "child.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, kill := context.WithCancel(context.Background())
			child := startOperationalChild(t, ctx, path)
			select {
			case <-child.ready:
			case logs := <-child.result:
				t.Fatalf("child stopped before readiness:\n%s", logs)
			case <-time.After(30 * time.Second):
				t.Fatal("child readiness timeout")
			}
			if _, err := fmt.Fprintln(child.input, "go"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(delay)
			kill() // exec.CommandContext sends SIGKILL
			logs := <-child.result
			died := !strings.Contains(logs, "--- PASS: TestOperationalHandoffChildProcess")
			var integrity string
			if err := f.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatalf("integrity after SIGKILL: %q %v", integrity, err)
			}
			killed := operationalPrestageStateAt(t, f)
			if killed.Posts > 1 || killed.Claims > 1 {
				t.Fatalf("after SIGKILL: %+v", killed)
			}
			out := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
			after := operationalPrestageStateAt(t, f)
			if after.Posts > 1 {
				t.Fatalf("a second POST after SIGKILL: before=%+v after=%+v out=%s", killed, after, operationalResultText(out))
			}
			var outcome string
			switch {
			case out.kind == operationalAccepted:
				if after.Posts != 1 || !after.Receipt {
					t.Fatalf("accepted without exactly one POST: %+v", after)
				}
				outcome = "completed"
			case after.Posts == 0 && after.Marker:
				outcome = "marker without sender"
			case after.Posts == 0 && (after.Stamp || after.StageEntries > 0):
				outcome = "stage residue"
			case after.Posts == 1:
				// The child sent; the survivor reconciles on a later call.
				again := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				if final := operationalPrestageStateAt(t, f); final.Posts != 1 {
					t.Fatalf("reconciliation sent again: %+v", final)
				}
				outcome = "sent by the child, " + fmt.Sprint(again.kind)
			default:
				t.Fatalf("unexpected state after SIGKILL (child died=%t): out=%s killed=%+v after=%+v", died, operationalResultText(out), killed, after)
			}
			if os.Getenv("ES_RT_KILL_LOGS") != "" {
				t.Logf("child logs:\n%s", logs)
			}
			outcomes[outcome]++
			t.Logf("child died=%t killed-state=%+v outcome=%s", died, killed, outcome)
		})
	}
	t.Logf("outcomes: %v", outcomes)
}
