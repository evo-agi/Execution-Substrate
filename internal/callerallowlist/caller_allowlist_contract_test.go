package callerallowlist_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agsconfig "execution-substrate/ags/config"
	arsconfig "execution-substrate/ars/config"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/testutil"
)

// callerAllowlistExampleWithPrefixes writes the repo's example configuration
// for one service with its allowlist replaced by prefixes, and returns the
// file's path.
func callerAllowlistExampleWithPrefixes(t *testing.T, example string, prefixes []string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testutil.Root, ".examples", "config", example))
	if err != nil {
		t.Fatalf("read example %s: %v", example, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode example %s: %v", example, err)
	}
	authorization, ok := doc["authorization"].(map[string]any)
	if !ok {
		t.Fatalf("example %s has no authorization object", example)
	}
	authorization["allowed_spiffe_path_prefixes"] = prefixes
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode example %s: %v", example, err)
	}
	path := filepath.Join(t.TempDir(), example)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// ARS, AGS and ES check their configured allowlist prefixes with the one
// shared rule in internal/callerallowlist (contracts.md section 3A): each
// service loads exactly the prefixes that rule accepts. The cases include
// every prefix of the PR 27 red-team's R6 table, where ARS and AGS loaded
// prefixes that ES refused and that no caller could ever match.
func TestARSAGSAndESCheckAllowlistPrefixesWithTheSharedRule(t *testing.T) {
	services := []struct {
		name    string
		example string
		load    func(string) error
	}{
		{"ARS", "ars.json", func(path string) error { _, err := arsconfig.Load(path); return err }},
		{"AGS", "ags.json", func(path string) error { _, err := agsconfig.Load(path); return err }},
		{"ES", "es.json", func(path string) error { _, err := esconfig.Load(path); return err }},
	}
	for _, tc := range []struct {
		prefixes []string
		want     error
	}{
		{prefixes: []string{"operator/local"}},
		{prefixes: []string{"service/execution", "service/artifact-governance", "operator/local"}},
		{prefixes: []string{"service/control-plane/provider"}},
		{prefixes: []string{"service"}, want: callerallowlist.ErrTooBroad},
		{prefixes: []string{"operator/local", "operator"}, want: callerallowlist.ErrTooBroad},
		{prefixes: []string{"spiffe://execution.internal/operator/local"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator//local"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator/./local"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator/../local"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"/operator/local/"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator/local/"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{" operator/local"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator/lo cal"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{"operator/local?x"}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{""}, want: callerallowlist.ErrNotCanonical},
		{prefixes: []string{}},
	} {
		for _, service := range services {
			err := service.load(callerAllowlistExampleWithPrefixes(t, service.example, tc.prefixes))
			switch {
			case len(tc.prefixes) == 0:
				if err == nil || !strings.Contains(err.Error(), "authorization.allowed_spiffe_path_prefixes is required") {
					t.Errorf("%s with no prefixes: %v, want the allowlist to be required", service.name, err)
				}
			case tc.want == nil:
				if err != nil {
					t.Errorf("%s refused valid prefixes %q: %v", service.name, tc.prefixes, err)
				}
			default:
				if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "authorization.allowed_spiffe_path_prefixes[") {
					t.Errorf("%s with prefixes %q: %v, want %v for authorization.allowed_spiffe_path_prefixes", service.name, tc.prefixes, err, tc.want)
				}
			}
		}
	}
}
