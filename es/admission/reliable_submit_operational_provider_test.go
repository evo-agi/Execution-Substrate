package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	requests               []operationalReceivedRequest
}

// operationalReceivedRequest is what the fake Nomad saw of one request: its
// method, path and query, and every value of its token header.
type operationalReceivedRequest struct {
	method, path, query string
	tokens              []string
}

func (r *operationalReceiver) received() []operationalReceivedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]operationalReceivedRequest(nil), r.requests...)
}

func (r *operationalReceiver) counts() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.posts, r.gets, r.redirects
}

func (r *operationalReceiver) handler(w http.ResponseWriter, q *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, operationalReceivedRequest{method: q.Method, path: q.URL.Path, query: q.URL.RawQuery,
		tokens: append([]string(nil), q.Header.Values(nomadTokenHeader)...)})
	r.mu.Unlock()
	if q.URL.Path == "/unexpected" {
		r.mu.Lock()
		r.redirects++
		r.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Like a Nomad with ACLs on, the fake refuses a request that does not carry
	// ES's token before it looks at anything else.
	if tokens := q.Header.Values(nomadTokenHeader); len(tokens) != 1 || tokens[0] != testNomadToken {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Permission denied"))
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

// TestOperationalProviderSendsItsTokenOnlyOverTLS13 shows that the
// provider, like ES's ordinary Nomad client, completes no handshake with a
// Nomad that offers only TLS 1.2, even one with the pinned key, so its token
// and request never leave ES; the same Nomad offering TLS 1.3 gets the request.
func TestOperationalProviderSendsItsTokenOnlyOverTLS13(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxVersion uint16
		delivered  bool
	}{
		{"TLS 1.3", tls.VersionTLS13, true},
		{"TLS 1.2 only", tls.VersionTLS12, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Header.Get(nomadTokenHeader) != testNomadToken {
					t.Errorf("request over TLS %v with token %t", r.TLS, r.Header.Get(nomadTokenHeader) == testNomadToken)
				}
				w.WriteHeader(http.StatusTeapot)
			}))
			server.TLS = &tls.Config{MaxVersion: tc.maxVersion}
			server.StartTLS()
			defer server.Close()
			target, err := netip.ParseAddrPort(strings.TrimPrefix(server.URL, "https://"))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			template := operationalProofTemplate(t)
			realm := operationalRealm{
				host: "127.0.0.1", port: target.Port(), region: "global",
				spki:     sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo),
				template: sha256.Sum256(operationalFrame([]byte("ESOHJTPL1"), template)),
			}
			provider, err := newOperationalLoopbackProvider(realm, target, roots, template, testNomadToken)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := provider.prepareRegister(context.Background(), []byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.cancel()
			response, reason := provider.exchange(prepared, 4096)
			if tc.delivered {
				if reason != reliablesubmit.OperationalHTTPRefusal || response.status != http.StatusTeapot || requests.Load() != 1 {
					t.Fatalf("reason=%v status=%d requests=%d", reason, response.status, requests.Load())
				}
				return
			}
			if reason != reliablesubmit.OperationalIO || response.status != 0 || requests.Load() != 0 {
				t.Fatalf("a TLS 1.2-only Nomad: reason=%v status=%d requests=%d", reason, response.status, requests.Load())
			}
		})
	}
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

// TestEveryOperationalNomadRequestCarriesTheTokenAndTheOperationalNamespace is
// the runtime half of PR #31's token guard for the operational provider. It
// drives one handoff that registers the job and observes it, and checks that
// each of the provider's three requests carried ES's token once, in the
// header only, and named the operational region and namespace.
func TestEveryOperationalNomadRequestCarriesTheTokenAndTheOperationalNamespace(t *testing.T) {
	f := makeOperationalFixture(t, "")
	result := f.service.handoffOperational(context.Background(), f.domain, f.domain.caller, f.raw)
	if result.kind != operationalAccepted {
		t.Fatalf("handoff result kind = %d, want accepted", result.kind)
	}
	seen := map[string]int{}
	for _, request := range f.receiver.received() {
		kind := request.method + " " + request.path
		if strings.HasPrefix(request.path, "/v1/job/esoh-job-") {
			kind = request.method + " /v1/job/<name>"
			if strings.HasSuffix(request.path, "/evaluations") {
				kind += "/evaluations"
			}
		}
		seen[kind]++
		if len(request.tokens) != 1 || request.tokens[0] != testNomadToken {
			t.Errorf("%s carried %d token header(s) or the wrong token", kind, len(request.tokens))
		}
		if request.query != "region=global&namespace="+operationalNamespace {
			t.Errorf("%s query = %q", kind, request.query)
		}
		if strings.Contains(request.query, testNomadToken) || strings.Contains(request.path, testNomadToken) {
			t.Errorf("%s put the token into the URL", kind)
		}
	}
	want := map[string]int{"POST /v1/jobs": 1, "GET /v1/job/<name>": 1, "GET /v1/job/<name>/evaluations": 1}
	if len(seen) != len(want) {
		t.Fatalf("requests = %v, want %v", seen, want)
	}
	for kind, count := range want {
		if seen[kind] != count {
			t.Fatalf("requests = %v, want %v", seen, want)
		}
	}
}

// TestOperationalProviderRefusesARequestWithoutTheToken shows that the fake
// Nomad above enforces the token, so the handoff tests that pass through it
// prove the token is sent: with another token the registration is refused and
// nothing is accepted.
func TestOperationalProviderRefusesARequestWithoutTheToken(t *testing.T) {
	f := makeOperationalFixture(t, "")
	f.domain.provider.token = "a1b2c3d4-0000-4000-8000-000000000031"
	result := f.service.handoffOperational(context.Background(), f.domain, f.domain.caller, f.raw)
	if result.kind == operationalAccepted {
		t.Fatal("a handoff with another token was accepted")
	}
	if posts, _, _ := f.receiver.counts(); posts != 0 {
		t.Fatalf("the fake Nomad registered %d job(s) without ES's token", posts)
	}
	received := f.receiver.received()
	if len(received) == 0 || received[0].method != http.MethodPost || received[0].path != "/v1/jobs" {
		t.Fatalf("the registration was not attempted: %v", received)
	}
}

// TestOperationalProviderNeedsANomadToken shows that the provider cannot be
// built without ES's Nomad token in its canonical form, so it cannot send a
// request without one.
func TestOperationalProviderNeedsANomadToken(t *testing.T) {
	_, server, target, pin := newOperationalTestReceiver(t, "")
	template := operationalProofTemplate(t)
	realm := operationalRealm{spki: pin, host: "127.0.0.1", port: target.Port(), region: "global",
		template: sha256.Sum256(operationalFrame([]byte("ESOHJTPL1"), template))}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if _, err := newOperationalLoopbackProvider(realm, target, roots, template, testNomadToken); err != nil {
		t.Fatalf("the canonical token was refused: %v", err)
	}
	for name, token := range map[string]string{
		"empty":               "",
		"trailing line feed":  testNomadToken + "\n",
		"upper case":          strings.ToUpper(testNomadToken),
		"short":               testNomadToken[1:],
		"not a UUID":          strings.Repeat("a", len(testNomadToken)),
		"surrounding space":   " " + testNomadToken[1:],
		"management-like tag": "management",
	} {
		t.Run(name, func(t *testing.T) {
			if provider, err := newOperationalLoopbackProvider(realm, target, roots, template, token); err == nil || provider != nil {
				t.Fatalf("token %q was accepted", token)
			}
		})
	}
}
