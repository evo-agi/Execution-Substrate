package callerallowlist_test

import (
	"errors"
	"strings"
	"testing"

	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/callerauth"
)

func mustID(t *testing.T, path string) callerauth.SPIFFEID {
	t.Helper()
	id, err := callerauth.ParseSPIFFEID("spiffe://" + callerauth.TrustDomain + "/" + path)
	if err != nil {
		t.Fatalf("parse caller path %q: %v", path, err)
	}
	return id
}

// ValidPrefixes and the refused prefixes below include every prefix of the
// PR 27 red-team's R6 table.
var validPrefixes = []string{
	"operator/local",
	"service/control-plane",
	"service/control-plane/provider",
	"service/artifact-governance",
	"Service/Execution",
	"a/b",
	"a.b/c_d-e",
	"x/..y",
	"x/y..",
	"x/.y",
	"workloads/codex-agent",
	"service/workload",
	"a/workload/b",
}

// workloadPrefixes name workload identities, which are never callers
// (.docs/system_overview/contracts.md, section 3A).
var workloadPrefixes = []string{
	"workload",
	"workload/codex-agent",
	"workload/codex-agent/run/r1",
	"Workload/codex-agent",
	"WORKLOAD/codex-agent",
	"wOrKlOaD/x",
}

var notCanonicalPrefixes = []string{
	"",
	" ",
	"/",
	".",
	"..",
	"/operator/local",
	"operator/local/",
	"/operator/local/",
	"operator//local",
	"operator/./local",
	"operator/../local",
	"operator/local/..",
	" operator/local",
	"operator/local ",
	"operator/lo cal",
	"operator/lo\tcal",
	"operator/local\n",
	"spiffe://execution.internal/operator/local",
	"operator/local?x=1",
	"operator/local#x",
	"operator/local%2Fx",
	"operator/lo%63al",
	"operator/löcal",
	"operator/local:8443",
	"user@operator/local",
	"operator\\local",
	"operator/local\x00",
}

var tooBroadPrefixes = []string{
	"service",
	"operator",
	"Service",
	"a",
}

func TestValidatePrefixAcceptsCanonicalPathsOfAtLeastTwoSegments(t *testing.T) {
	for _, prefix := range validPrefixes {
		if err := callerallowlist.ValidatePrefix(prefix); err != nil {
			t.Errorf("ValidatePrefix(%q) = %v, want nil", prefix, err)
		}
	}
}

func TestValidatePrefixRefusesPathsNoCallerCanPresent(t *testing.T) {
	for _, prefix := range notCanonicalPrefixes {
		if err := callerallowlist.ValidatePrefix(prefix); !errors.Is(err, callerallowlist.ErrNotCanonical) {
			t.Errorf("ValidatePrefix(%q) = %v, want ErrNotCanonical", prefix, err)
		}
	}
}

func TestValidatePrefixRefusesWorkloadIdentities(t *testing.T) {
	for _, prefix := range workloadPrefixes {
		if err := callerallowlist.ValidatePrefix(prefix); !errors.Is(err, callerallowlist.ErrWorkloadPrefix) {
			t.Errorf("ValidatePrefix(%q) = %v, want ErrWorkloadPrefix", prefix, err)
		}
	}
	// No workload caller can reach MatchesAny at all: callerauth.ParseSPIFFEID
	// refuses every workload identity, so no callerauth.SPIFFEID with a
	// workload path exists (TestParseSPIFFEIDRefusesEverythingElse). The
	// guarantee is structural, and this test does not try to restate it.
	if err := callerallowlist.ValidatePrefixes("allowed_caller_prefixes", []string{"operator/local", "workload/codex-agent"}); !errors.Is(err, callerallowlist.ErrWorkloadPrefix) || !strings.Contains(err.Error(), "allowed_caller_prefixes[1]") {
		t.Errorf("ValidatePrefixes with a workload prefix = %v, want ErrWorkloadPrefix naming entry 1", err)
	}
}

func TestValidatePrefixRefusesOneSegmentPrefixes(t *testing.T) {
	for _, prefix := range tooBroadPrefixes {
		if err := callerallowlist.ValidatePrefix(prefix); !errors.Is(err, callerallowlist.ErrTooBroad) {
			t.Errorf("ValidatePrefix(%q) = %v, want ErrTooBroad", prefix, err)
		}
	}
}

func TestValidatePrefixesNamesTheFieldAndTheEntry(t *testing.T) {
	const field = "authorization.allowed_spiffe_path_prefixes"
	if err := callerallowlist.ValidatePrefixes(field, []string{"operator/local", "service/control-plane"}); err != nil {
		t.Fatalf("valid allowlist: %v", err)
	}
	for _, prefixes := range [][]string{nil, {}} {
		err := callerallowlist.ValidatePrefixes(field, prefixes)
		if err == nil || err.Error() != field+" is required" {
			t.Fatalf("empty allowlist %#v: %v, want %q", prefixes, err, field+" is required")
		}
	}
	err := callerallowlist.ValidatePrefixes(field, []string{"operator/local", "service"})
	if !errors.Is(err, callerallowlist.ErrTooBroad) || !strings.HasPrefix(err.Error(), field+"[1]: ") {
		t.Fatalf("one-segment second entry: %v", err)
	}
	err = callerallowlist.ValidatePrefixes(field, []string{"operator/lo cal", "operator/local"})
	if !errors.Is(err, callerallowlist.ErrNotCanonical) || !strings.HasPrefix(err.Error(), field+"[0]: ") {
		t.Fatalf("non-canonical first entry: %v", err)
	}
}

func TestMatchesIsExactOrBelowAValidPrefix(t *testing.T) {
	for _, tc := range []struct {
		path, prefix string
		want         bool
	}{
		{"operator/local", "operator/local", true},
		{"operator/local/a", "operator/local", true},
		{"operator/local/a/b", "operator/local", true},
		{"service/control-plane/provider", "service/control-plane", true},
		{"operator/local-evil", "operator/local", false},
		{"operator/locala", "operator/local", false},
		{"operator", "operator/local", false},
		{"operator/loca", "operator/local", false},
		{"Operator/Local", "operator/local", false},
		{"service/deployment", "service/control-plane", false},
		// A prefix that fails ValidatePrefix matches nothing, not even the
		// path it spells after trimming or the paths below it.
		{"service/execution", "service", false},
		{"operator/local", "/operator/local", false},
		{"operator/local", "operator/local/", false},
		{"operator/local/a", "operator/local/", false},
		{"operator/local", " operator/local", false},
		{"operator/local", "spiffe://execution.internal/operator/local", false},
		{"operator/local", "", false},
	} {
		if got := callerallowlist.Matches(mustID(t, tc.path), tc.prefix); got != tc.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
	if callerallowlist.Matches(callerauth.SPIFFEID{}, "operator/local") {
		t.Errorf("the zero SPIFFEID matched a prefix")
	}
}

func TestMatchesAnyNeedsOneMatchingPrefix(t *testing.T) {
	id := mustID(t, "service/control-plane/provider")
	if !callerallowlist.MatchesAny(id, []string{"operator/local", "service/control-plane"}) {
		t.Errorf("MatchesAny missed the second prefix")
	}
	if callerallowlist.MatchesAny(id, []string{"operator/local", "service", "service/control-plane/"}) {
		t.Errorf("MatchesAny matched no valid prefix")
	}
	if callerallowlist.MatchesAny(id, nil) {
		t.Errorf("MatchesAny matched an empty allowlist")
	}
}

// Every valid prefix is matched by the caller whose path it is, so a prefix
// that passes the configuration check is never dead policy.
func TestEveryValidPrefixIsMatchedByItsOwnCaller(t *testing.T) {
	for _, prefix := range validPrefixes {
		if !callerallowlist.Matches(mustID(t, prefix), prefix) {
			t.Errorf("valid prefix %q does not match its own caller", prefix)
		}
	}
}

// FuzzPrefixRule checks the package against callerauth for any prefix: a
// prefix is valid exactly when it is the path of an ID callerauth accepts and
// has at least two segments, a valid prefix matches its own caller, and an
// invalid prefix matches no caller.
func FuzzPrefixRule(f *testing.F) {
	for _, seed := range append(append(append([]string{}, validPrefixes...), notCanonicalPrefixes...), tooBroadPrefixes...) {
		f.Add(seed)
	}
	probes := []string{"operator/local", "operator/local/a", "service/control-plane", "service/execution", "a/b", "a/b/c"}
	f.Fuzz(func(t *testing.T, prefix string) {
		id, parseErr := callerauth.ParseSPIFFEID("spiffe://" + callerauth.TrustDomain + "/" + prefix)
		wantValid := parseErr == nil && id.Path() == prefix && strings.Count(prefix, "/") >= 1
		err := callerallowlist.ValidatePrefix(prefix)
		if (err == nil) != wantValid {
			t.Fatalf("ValidatePrefix(%q) = %v, want valid=%v", prefix, err, wantValid)
		}
		if err == nil {
			if !callerallowlist.Matches(id, prefix) {
				t.Fatalf("valid prefix %q does not match its own caller", prefix)
			}
			return
		}
		for _, path := range probes {
			if callerallowlist.Matches(mustID(t, path), prefix) {
				t.Fatalf("invalid prefix %q matched %q", prefix, path)
			}
		}
	})
}
