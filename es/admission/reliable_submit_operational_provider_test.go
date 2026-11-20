package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

const operationalTestEvaluation = "14495513-ef66-49c8-a917-a4aabd29e367"
const operationalTestIndex = 73

func operationalProofTemplate(t *testing.T) []byte {
	t.Helper()
	slots := func(path string, names ...string) map[string]any {
		m := map[string]any{}
		for _, name := range names {
			m[name] = map[string]string{"$job0": path + "/" + name}
		}
		return m
	}
	top := slots("", "ID", "Name", "Region", "Namespace", "Priority", "Type", "Meta", "Datacenters")
	groupPath := "/TaskGroups/0"
	group := slots(groupPath, "Name", "Count")
	group["RestartPolicy"] = slots(groupPath+"/RestartPolicy", "Attempts", "Mode", "Interval", "Delay")
	group["ReschedulePolicy"] = slots(groupPath+"/ReschedulePolicy", "Attempts", "Unlimited", "Delay", "DelayFunction", "MaxDelay")
	taskPath := groupPath + "/Tasks/0"
	task := slots(taskPath, "Name", "Driver", "User", "Env")
	task["Resources"] = slots(taskPath+"/Resources", "CPU", "MemoryMB")
	task["Meta"] = slots(taskPath+"/Meta", "run_id", "artifact_digest", "derivation_spec_digest", "output_id")
	task["Config"] = slots(taskPath+"/Config", "image", "command", "args", "privileged", "security_opt", "mounts", "network_mode")
	group["Tasks"] = []any{task}
	top["TaskGroups"] = []any{group}
	top["Stop"] = false
	top["Periodic"] = nil
	top["ParameterizedJob"] = nil
	body, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type operationalReceiver struct {
	mu                     sync.Mutex
	posts, gets, redirects int
	mode                   string
	job                    json.RawMessage
	entered                chan struct{}
	release                chan struct{}
	sink                   string
	observeEntered         chan struct{}
	observeRelease         chan struct{}
}

func (r *operationalReceiver) counts() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.posts, r.gets, r.redirects
}

func (r *operationalReceiver) handler(w http.ResponseWriter, q *http.Request) {
	if q.URL.Path == "/unexpected" {
		r.mu.Lock()
		r.redirects++
		r.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if q.URL.RawQuery != "region=global&namespace=es-operational-v1" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	mode := r.mode
	if q.Method == "POST" && q.URL.Path == "/v1/jobs" {
		r.posts++
		r.mu.Unlock()
		if r.entered != nil {
			r.entered <- struct{}{}
			<-r.release
		}
		if mode == "redirect307" || mode == "redirect308" {
			code := http.StatusTemporaryRedirect
			if mode == "redirect308" {
				code = http.StatusPermanentRedirect
			}
			w.Header().Set("Location", r.sink)
			w.WriteHeader(code)
			return
		}
		var input struct {
			Job            json.RawMessage
			EnforceIndex   bool
			JobModifyIndex int
		}
		if err := json.NewDecoder(q.Body).Decode(&input); err != nil || !input.EnforceIndex || input.JobModifyIndex != 0 || len(input.Job) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		if r.job != nil {
			r.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			return
		}
		r.job = bytes.Clone(input.Job)
		r.mu.Unlock()
		if mode == "conflict" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if mode == "lost-post" || mode == "lost-post-before-observation" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Nomad-Index", "73")
		_, _ = fmt.Fprintf(w, `{"EvalID":%q,"EvalCreateIndex":73,"JobModifyIndex":73,"Index":73,"LastContact":0,"KnownLeader":false,"NextToken":"","Warnings":""}`, operationalTestEvaluation)
		return
	}
	if q.Method != "GET" || !strings.HasPrefix(q.URL.Path, "/v1/job/esoh-job-") {
		r.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.gets++
	job := bytes.Clone(r.job)
	observeEntered, observeRelease := r.observeEntered, r.observeRelease
	r.mu.Unlock()
	if mode == "observation-timeout" {
		<-q.Context().Done()
		return
	}
	if job == nil || mode == "inconclusive" || mode == "lost-post-before-observation" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Nomad-Index", "73")
	w.Header().Set("X-Nomad-KnownLeader", "true")
	w.Header().Set("X-Nomad-LastContact", "0")
	if mode == "weak" {
		w.Header().Set("X-Nomad-KnownLeader", "false")
	}
	var expanded map[string]any
	if json.Unmarshal(job, &expanded) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	jobID := expanded["ID"]
	if strings.HasSuffix(q.URL.Path, "/evaluations") {
		if observeEntered != nil {
			observeEntered <- struct{}{}
			select {
			case <-observeRelease:
			case <-q.Context().Done():
				return
			}
		}
		if mode == "missing-evaluation" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		evaluation := map[string]any{"ID": operationalTestEvaluation, "Namespace": operationalNamespace, "JobID": jobID,
			"Type": "batch", "Priority": 50, "TriggeredBy": "job-register", "CreateIndex": 73, "ModifyIndex": 73, "JobModifyIndex": 73}
		switch mode {
		case "wrong-index":
			evaluation["JobModifyIndex"] = 72
		case "wrong-eval":
			evaluation["TriggeredBy"] = "unrelated"
		case "foreign-evaluation":
			evaluation["JobID"] = "disjoint"
		case "duplicate-evaluation":
			_ = json.NewEncoder(w).Encode([]any{evaluation, evaluation})
			return
		}
		_ = json.NewEncoder(w).Encode([]any{evaluation})
		return
	}
	for k, v := range map[string]any{"CreateIndex": 73, "JobModifyIndex": 73, "ModifyIndex": 73, "Version": 0,
		"Status": "pending", "StatusDescription": "", "Stable": false, "SubmitTime": 17,
		"Stop": false, "Periodic": nil, "ParameterizedJob": nil} {
		expanded[k] = v
	}
	switch mode {
	case "foreign-job":
		expanded["ID"] = "disjoint"
	case "wrong-job-index":
		expanded["JobModifyIndex"] = 72
	case "extra-field":
		expanded["UnexpectedEffect"] = true
	case "wrong-carrier":
		expanded["Meta"].(map[string]any)[operationalCorrelation] = "foreign"
	case "changed-default":
		expanded["Stop"] = true
	case "duplicate":
		_, _ = w.Write([]byte(`{"ID":"a","ID":"b"}`))
		return
	case "oversize":
		_, _ = w.Write(bytes.Repeat([]byte{' '}, 262145))
		return
	}
	_ = json.NewEncoder(w).Encode(expanded)
}

func newOperationalTestReceiver(t *testing.T, mode string) (*operationalReceiver, *httptest.Server, netip.AddrPort, [32]byte) {
	t.Helper()
	r := &operationalReceiver{mode: mode}
	s := httptest.NewTLSServer(http.HandlerFunc(r.handler))
	t.Cleanup(s.Close)
	r.sink = s.URL + "/unexpected"
	target, err := netip.ParseAddrPort(strings.TrimPrefix(s.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return r, s, target, sha256.Sum256(s.Certificate().RawSubjectPublicKeyInfo)
}

func TestOperationalHandoffProviderExchange(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		accepted   bool
	}{
		{"ExactPairedObservation", "", true}, {"LostResponseAfterIngress", "lost-post", true},
		{"Redirect307", "redirect307", false}, {"Redirect308", "redirect308", false},
		{"Qualified404", "inconclusive", false}, {"CollisionResponse", "conflict", false}, {"WeakObservation", "weak", false},
		{"ObservationTimeout", "observation-timeout", false}, {"MissingInitialEvaluation", "missing-evaluation", false},
		{"WrongIndex", "wrong-index", false}, {"WrongEvaluation", "wrong-eval", false},
		{"ForeignJob", "foreign-job", false}, {"ForeignEvaluation", "foreign-evaluation", false},
		{"WrongJobIndex", "wrong-job-index", false}, {"DuplicateEvaluation", "duplicate-evaluation", false},
		{"ExtraProjection", "extra-field", false},
		{"TamperedCarrier", "wrong-carrier", false}, {"ChangedDefault", "changed-default", false},
		{"DuplicateJSON", "duplicate", false}, {"Oversize", "oversize", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeOperationalFixture(t, tc.mode)
			var postEntry, getEntry atomic.Int32
			f.domain.provider.exchangeEntry = func(method string) {
				if method == http.MethodPost {
					postEntry.Add(1)
				} else if method == http.MethodGet {
					getEntry.Add(1)
				}
			}
			defer func() { f.domain.provider.exchangeEntry = nil }()
			ctx, getConn := operationalGetConnEvents()
			result := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
			posts, gets, redirects := f.receiver.counts()
			if postEntry.Load() != 1 || getEntry.Load() != int32(gets) || int(getConn.Load()) != posts+gets+redirects {
				t.Fatalf("extra GetConn events: entries=%d ingress=%d", getConn.Load(), posts+gets+redirects)
			}
			if tc.mode == "conflict" && gets != 0 {
				t.Fatal("collision response was treated as a lost acknowledgment")
			}
			if posts != 1 || redirects != 0 || (result.kind == operationalAccepted) != tc.accepted || result.run == "" {
				t.Fatalf("result kind=%d disposition=%d assigned=%t posts=%d redirect=%d", result.kind, result.write, result.run != "", posts, redirects)
			}
			again := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
			if posts, gets, redirects = f.receiver.counts(); posts != 1 || redirects != 0 || again.run != result.run || postEntry.Load() != 1 || getEntry.Load() != int32(gets) || int(getConn.Load()) != posts+gets+redirects {
				t.Fatalf("replay changed run or delivery: posts=%d redirects=%d GetConn events=%d phase=%d", posts, redirects, getConn.Load(), again.kind)
			}
		})
	}
	t.Run("ClientEntriesAndLostIngressRestart", testOperationalLostIngressRestart)
	t.Run("StrictJSONNumbersAndUnicode", func(t *testing.T) {
		for _, raw := range []string{`-0`, `1e0`, `2.0`, `18446744073709551616`, `-9223372036854775809`, `"\ud800"`, `{"a":1,"\u0061":2}`} {
			if _, err := parseOperationalJSON([]byte(raw), 65536); err == nil {
				t.Fatalf("accepted invalid case %q", raw)
			}
		}
		for _, raw := range []string{`18446744073709551615`, `-9223372036854775808`, `"\ud83d\ude03"`, `null`} {
			if _, err := parseOperationalJSON([]byte(raw), 65536); err != nil {
				t.Fatalf("refused valid case %q: %v", raw, err)
			}
		}
	})
}

func TestOperationalHandoffFiniteFailureReasons(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want reliablesubmit.OperationalReason
	}{
		{"observation-timeout", reliablesubmit.OperationalTimeout},
		{"lost-post-before-observation", reliablesubmit.OperationalIO},
		{"inconclusive", reliablesubmit.OperationalHTTPRefusal},
		{"oversize", reliablesubmit.OperationalMalformed},
		{"weak", reliablesubmit.OperationalContinuity},
		{"missing-evaluation", reliablesubmit.OperationalInconclusive},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := makeOperationalFixture(t, tc.mode)
			first := f.submit()
			if first.kind != operationalAmbiguous || first.reason != tc.want || first.write != reliablesubmit.OperationalMarkerDirect ||
				first.operation != reliablesubmit.OperationalMark || first.run == "" || first.receipt.Valid() {
				t.Fatalf("reason=%v want=%v kind=%v disposition=%v", first.reason, tc.want, first.kind, first.write)
			}
			if posts, _, redirects := f.receiver.counts(); posts != 1 || redirects != 0 {
				t.Fatalf("ambiguous exchange caused extra ingress: posts=%d redirects=%d", posts, redirects)
			}
		})
	}
}

func operationalGetConnEvents() (context.Context, *atomic.Int32) {
	return operationalGetConnEventsOn(context.Background())
}

func operationalGetConnEventsOn(parent context.Context) (context.Context, *atomic.Int32) {
	entries := new(atomic.Int32)
	ctx := httptrace.WithClientTrace(parent, &httptrace.ClientTrace{
		GetConn: func(string) { entries.Add(1) },
	})
	return ctx, entries
}

func testOperationalLostIngressRestart(t *testing.T) {
	f := makeOperationalFixture(t, "lost-post-before-observation")
	var postEntry, getEntry atomic.Int32
	f.domain.provider.exchangeEntry = func(method string) {
		if method == http.MethodPost {
			postEntry.Add(1)
		} else if method == http.MethodGet {
			getEntry.Add(1)
		}
	}
	defer func() { f.domain.provider.exchangeEntry = nil }()
	ctx, getConn := operationalGetConnEvents()
	first := f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw)
	posts, gets, redirects := f.receiver.counts()
	if first.kind != operationalAmbiguous || first.run == "" || first.receipt.Valid() ||
		posts != 1 || gets != 1 || redirects != 0 || postEntry.Load() != 1 || getEntry.Load() != 1 || getConn.Load() != 2 {
		t.Fatalf("lost acknowledgement: result=%d GetConn events=%d posts=%d gets=%d redirects=%d", first.kind, getConn.Load(), posts, gets, redirects)
	}
	if err := f.domain.custody.Close(); err != nil {
		t.Fatal(err)
	}
	f.receiver.mu.Lock()
	f.receiver.mode = ""
	f.receiver.mu.Unlock()
	reopened := f.reopen()
	accepted := (&Service{}).recoverOperational(ctx, reopened, reopened.caller, f.raw)
	posts, gets, redirects = f.receiver.counts()
	if accepted.kind != operationalAccepted || accepted.run != first.run || !accepted.receipt.Valid() ||
		posts != 1 || gets != 3 || redirects != 0 || postEntry.Load() != 1 || getEntry.Load() != 3 || getConn.Load() != 4 {
		t.Fatalf("post-restart observation: result=%d GetConn events=%d posts=%d gets=%d redirects=%d", accepted.kind, getConn.Load(), posts, gets, redirects)
	}
	t.Log("four GetConn events across restart, one POST, three GETs and zero redirect ingress")
}
