package app_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

// todaysWorkloadGrants is the admission policy that keeps today's flows: the
// workload grants scripts/72_supported_local_setup.sh, the example
// configurations and the Remote Alpha upgrade write
// (.docs/system_overview/configuration.md). For each <prefix> in
// esAllowedPrefixes, ES's caller allowlist, the principal
// spiffe://execution.internal/<prefix> gets the lane unrestricted for the
// static-script runs it published and calls itself, on both runtime
// profiles, signed with signerKeyID, the key ES verifies artifact evidence
// with. ES admits a run that requests the network only with a grant that
// names its publisher and its caller.
func todaysWorkloadGrants(esAllowedPrefixes []string, signerKeyID string) *esconfig.AdmissionPolicyConfig {
	reaches := true
	grants := &esconfig.WorkloadGrantsConfig{
		EgressLanes: []esconfig.WorkloadEgressLaneConfig{{Name: esconfig.WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}},
	}
	for _, prefix := range esAllowedPrefixes {
		for _, profile := range []struct{ id, name string }{
			{"default", esconfig.WorkloadGrantRuntimeProfileDefault},
			{"normal-shell", esconfig.WorkloadGrantRuntimeProfileControlPlaneNormalShell},
		} {
			grants.Rules = append(grants.Rules, esconfig.WorkloadGrantRuleConfig{
				ID:                 fmt.Sprintf("%s-%s", strings.ReplaceAll(prefix, "/", "-"), profile.id),
				PublisherPrincipal: "spiffe://execution.internal/" + prefix,
				CallerPrincipal:    "spiffe://execution.internal/" + prefix,
				SignerKeyID:        signerKeyID,
				ArtifactType:       "static-script",
				RuntimeProfile:     profile.name,
				EgressLane:         esconfig.WorkloadEgressLaneUnrestricted,
			})
		}
	}
	return &esconfig.AdmissionPolicyConfig{WorkloadGrants: grants}
}

// Every ES configuration an es/app test builds names its admission policy,
// so no fixture can leave out the workload grants by accident: without them
// ES refuses every run that requests the network, and a fixture that forgot
// them fails only where Docker and Nomad run.
func TestEveryESConfigFixtureNamesItsAdmissionPolicy(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	literals := 0
	for _, name := range files {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			selector, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Config" {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "esconfig" {
				return true
			}
			literals++
			for _, element := range literal.Elts {
				if field, ok := element.(*ast.KeyValueExpr); ok {
					if key, ok := field.Key.(*ast.Ident); ok && key.Name == "AdmissionPolicy" {
						return true
					}
				}
			}
			t.Errorf("%s: an ES configuration without AdmissionPolicy; use todaysWorkloadGrants or name the policy the test needs", fset.PositionFor(literal.Pos(), false))
			return true
		})
	}
	if literals < 4 {
		t.Fatalf("found %d esconfig.Config literals in es/app tests: the scan no longer sees the fixtures", literals)
	}
}
