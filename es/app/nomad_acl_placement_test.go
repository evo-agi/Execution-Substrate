package app_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNomadForPlacement answers the requests of nomad_acl.py placement like a
// locked Nomad: only the observer token reads nodes, and only the ES token
// plans, in ES's namespace. It records each plan body.
type fakeNomadForPlacement struct {
	mu          sync.Mutex
	nodes       []map[string]any
	detail      func(call int) map[string]any
	plan        func(mode string) map[string]any
	detailCalls int
	requests    int
	plans       []map[string]any
	planPaths   []string
}

func (f *fakeNomadForPlacement) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	token := r.Header.Get("X-Nomad-Token")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/nodes" && token == testObserverNomadToken:
		_ = json.NewEncoder(w).Encode(f.nodes)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/node/node-a-id" && token == testObserverNomadToken:
		f.detailCalls++
		_ = json.NewEncoder(w).Encode(f.detail(f.detailCalls))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/job/") && strings.HasSuffix(r.URL.Path, "/plan") &&
		token == testESNomadToken && r.URL.Query().Get("namespace") == nomadACLNamespace:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.plans = append(f.plans, body)
		f.planPaths = append(f.planPaths, r.URL.Path)
		mode := ""
		if job, ok := body["Job"].(map[string]any); ok {
			if groups, ok := job["TaskGroups"].([]any); ok && len(groups) == 1 {
				if tasks, ok := groups[0].(map[string]any)["Tasks"].([]any); ok && len(tasks) == 1 {
					if config, ok := tasks[0].(map[string]any)["Config"].(map[string]any); ok {
						mode, _ = config["network_mode"].(string)
					}
				}
			}
		}
		_ = json.NewEncoder(w).Encode(f.plan(mode))
	default:
		w.WriteHeader(http.StatusForbidden)
	}
}

func placementNodeStub(eligibility string) map[string]any {
	return map[string]any{"ID": "node-a-id", "Name": "node-a", "Status": "ready", "SchedulingEligibility": eligibility}
}

// placementNodeDetail has the fields of a real node detail that placement
// reads; networkModes lists the modes of NodeResources.Networks.
func placementNodeDetail(updatedAt int64, dockerHealthy bool, networkModes ...string) map[string]any {
	networks := []map[string]any{}
	for _, mode := range networkModes {
		network := map[string]any{"Mode": mode}
		if mode == "host" {
			network["Device"] = "lo"
			network["CIDR"] = "127.0.0.1/32"
			network["IP"] = "127.0.0.1"
		}
		networks = append(networks, network)
	}
	return map[string]any{
		"ID":              "node-a-id",
		"Name":            "node-a",
		"Status":          "ready",
		"StatusUpdatedAt": updatedAt,
		"Drivers":         map[string]any{"docker": map[string]any{"Detected": true, "Healthy": dockerHealthy}},
		"NodeResources":   map[string]any{"Networks": networks},
	}
}

func placementPlanPlaced(string) map[string]any {
	return map[string]any{"Annotations": map[string]any{"DesiredTGUpdates": map[string]any{"probe": map[string]any{"Place": 1}}}}
}

// placementPlanMissingNetwork is the plan answer the box's Nomad gave while
// its node had only a bridge network.
func placementPlanMissingNetwork(string) map[string]any {
	return map[string]any{
		"Annotations": map[string]any{"DesiredTGUpdates": map[string]any{"probe": map[string]any{"Place": 1}}},
		"FailedTGAllocs": map[string]any{"probe": map[string]any{
			"NodesEvaluated": 1, "NodesAvailable": map[string]any{"dc-test": 1},
			"ConstraintFiltered": map[string]any{"missing network": 1},
		}},
	}
}

func TestNomadACLToolPlacementChecksHostNetworkAndPlans(t *testing.T) {
	dir := t.TempDir()
	esTokenFile, err := writeNomadTokenFileAt(dir, "es-token", testESNomadToken)
	if err != nil {
		t.Fatal(err)
	}
	observerTokenFile, err := writeNomadTokenFileAt(dir, "observer-token", testObserverNomadToken)
	if err != nil {
		t.Fatal(err)
	}
	writeESConfig := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "es.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	esConfig := writeESConfig(t, `{"nomad": {"base_url": "http://127.0.0.1:4646", "datacenter": "dc-test"}}`)
	run := func(fake *fakeNomadForPlacement, config string, extra ...string) (string, error) {
		server := httptest.NewServer(fake)
		defer server.Close()
		args := append([]string{"placement", "--addr", server.URL, "--es-token-file", esTokenFile,
			"--observer-token-file", observerTokenFile, "--es-config", config}, extra...)
		return runNomadACLTool(t, args...)
	}
	now := time.Now().Unix()
	healthy := func(int) map[string]any { return placementNodeDetail(now, true, "bridge", "host") }

	t.Run("places both job shapes", func(t *testing.T) {
		fake := &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")}, detail: healthy, plan: placementPlanPlaced}
		output, err := run(fake, esConfig, "--wait-seconds", "0")
		if err != nil || !strings.Contains(output, "nomad placement: ok (host-mode network on node-a; ES's job shapes, network_mode none and bridge, plan in es-submit-v1, datacenter dc-test, with the ES token)") {
			t.Fatalf("placement: %v output=%s", err, output)
		}
		if len(fake.plans) != 2 {
			t.Fatalf("placement sent %d plans, want 2", len(fake.plans))
		}
		for i, mode := range []string{"none", "bridge"} {
			id := "es-placement-probe-" + mode
			if fake.planPaths[i] != "/v1/job/"+id+"/plan" {
				t.Fatalf("plan %d path %s", i, fake.planPaths[i])
			}
			// ES's job shape: Docker, the network mode, no Nomad network
			// block and no ports, in ES's namespace and datacenter. A plan
			// with no diff registers nothing.
			want := map[string]any{
				"Diff": false,
				"Job": map[string]any{
					"ID": id, "Name": id, "Type": "batch", "Namespace": nomadACLNamespace, "Datacenters": []any{"dc-test"},
					"TaskGroups": []any{map[string]any{
						"Name": "probe", "Count": float64(1),
						"Tasks": []any{map[string]any{
							"Name": "probe", "Driver": "docker",
							"Config":    map[string]any{"image": "alpine:3.20", "command": "/bin/true", "network_mode": mode},
							"Resources": map[string]any{"CPU": float64(100), "MemoryMB": float64(64)},
						}},
					}},
				},
			}
			if got, wantText := string(mustMarshalJSON(t, fake.plans[i])), string(mustMarshalJSON(t, want)); got != wantText {
				t.Fatalf("plan %d body\n%s\nwant\n%s", i, got, wantText)
			}
		}
	})

	t.Run("waits for the restarted client to register", func(t *testing.T) {
		startedAt := now - 5
		fake := &fakeNomadForPlacement{
			nodes: []map[string]any{placementNodeStub("eligible")},
			// Right after a restart the servers still serve the node as it
			// registered before, with the network it had then.
			detail: func(call int) map[string]any {
				if call < 3 {
					return placementNodeDetail(startedAt-60, true, "bridge", "host")
				}
				return placementNodeDetail(now, true, "bridge", "host")
			},
			plan: placementPlanPlaced,
		}
		output, err := run(fake, esConfig, "--fresh-after", strconv.FormatInt(startedAt, 10), "--wait-seconds", "30")
		if err != nil || !strings.Contains(output, "nomad placement: ok") || fake.detailCalls < 3 {
			t.Fatalf("placement after a restart: %v detail reads %d output=%s", err, fake.detailCalls, output)
		}
	})

	for _, test := range []struct {
		name   string
		fake   *fakeNomadForPlacement
		extra  []string
		want   []string
		noPlan bool
	}{
		{"no client node", &fakeNomadForPlacement{nodes: []map[string]any{}, plan: placementPlanPlaced}, nil,
			[]string{"(no nodes)"}, true},
		{"the node has only a bridge network, as the box's did with its cable out",
			&fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")},
				detail: func(int) map[string]any { return placementNodeDetail(now, true, "bridge") }, plan: placementPlanPlaced}, nil,
			[]string{"node-a=no-host-network", `pin network_interface = "lo" (scripts/70_linux_setup.sh)`, "on Wi-Fi and on a cable alike"}, true},
		{"the node is not eligible", &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("ineligible")},
			detail: healthy, plan: placementPlanPlaced}, nil, []string{"node-a=ready/ineligible"}, true},
		{"the node's Docker driver is unhealthy", &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")},
			detail: func(int) map[string]any { return placementNodeDetail(now, false, "bridge", "host") }, plan: placementPlanPlaced}, nil,
			[]string{"node-a=docker-unhealthy"}, true},
		{"the node has not registered since the start", &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")},
			detail: func(int) map[string]any { return placementNodeDetail(now-120, true, "bridge", "host") }, plan: placementPlanPlaced},
			[]string{"--fresh-after", strconv.FormatInt(now-60, 10)}, []string{"node-a=not-registered-since-the-start"}, true},
		{"a plan finds no node with the network the job needs", &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")},
			detail: healthy, plan: func(mode string) map[string]any {
				if mode == "bridge" {
					return placementPlanMissingNetwork(mode)
				}
				return placementPlanPlaced(mode)
			}}, nil,
			[]string{`a plan of ES's jobs in es-submit-v1, datacenter dc-test, places nothing: network_mode bridge: its allocation would fail (ConstraintFiltered {"missing network": 1})`}, false},
		{"a plan places nothing", &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")},
			detail: healthy, plan: func(string) map[string]any { return map[string]any{} }}, nil,
			[]string{"network_mode none: would place 0 of 1 | network_mode bridge: would place 0 of 1"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := run(test.fake, esConfig, append([]string{"--wait-seconds", "0"}, test.extra...)...)
			if err == nil {
				t.Fatalf("placement passed: %s", output)
			}
			for _, want := range test.want {
				if !strings.Contains(output, want) {
					t.Fatalf("placement refusal lacks %q: %s", want, output)
				}
			}
			if test.noPlan && len(test.fake.plans) != 0 {
				t.Fatalf("placement planned without a node that can take ES's jobs: %d plans", len(test.fake.plans))
			}
		})
	}

	// The datacenter comes from ES's own config; a config placement cannot
	// read safely stops it before any request.
	link := filepath.Join(t.TempDir(), "es.json")
	if err := os.Symlink(esConfig, link); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		config string
		want   string
	}{
		{"no nomad.datacenter", writeESConfig(t, `{"nomad": {"base_url": "http://127.0.0.1:4646"}}`), "names no valid nomad.datacenter"},
		{"a datacenter that is not a name", writeESConfig(t, `{"nomad": {"datacenter": "dc1\", \"other"}}`), "names no valid nomad.datacenter"},
		{"not JSON", writeESConfig(t, "nomad.datacenter = dc1\n"), "is not JSON"},
		{"a symbolic link", link, "is unavailable or is a symbolic link"},
		{"a relative path", "es.json", "--es-config"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeNomadForPlacement{nodes: []map[string]any{placementNodeStub("eligible")}, detail: healthy, plan: placementPlanPlaced}
			output, err := run(fake, test.config, "--wait-seconds", "0")
			if err == nil || !strings.Contains(output, test.want) || fake.requests != 0 {
				t.Fatalf("placement with ES config %s: %v requests %d output=%s", test.name, err, fake.requests, output)
			}
		})
	}
}
