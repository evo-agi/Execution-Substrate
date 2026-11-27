package executionsubstrate_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The lifecycle contract states which caller environment keys and mounts ES
// admits (.docs/execution_lifecycle/contracts.md, section 5). These tests keep
// that text and the reserved-key list in es/admission/service.go in step.

func prepareRequestContract(t *testing.T) string {
	t.Helper()
	return compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "## 5. Prepare contract", "### Response contract")
}

func TestCallerDeclarationRulesAreInTheLifecycleContract(t *testing.T) {
	contract := prepareRequestContract(t)
	assertContainsAll(t, "contracts.md section 5 caller declaration rules", contract,
		"The artifact's signed runtime interface, `claims.admission.execution.runtime` in the aggregate evidence, is the only source of what a caller may set in `invocation.env` or mount through `invocation.mounts`.",
		"Every environment key must be a portable name: an ASCII letter or underscore, followed by ASCII letters, digits and underscores.",
		"Environment keys must not use reserved keys, whether or not the artifact declares them.",
		"ES matches reserved keys with ASCII letters folded to upper case",
		"`TestReservedEnvironmentKeySetIsPinned` pins it.",
		"It is a backstop for a publisher's mistake, not the boundary",
		"They do not include every such key; the families below add more",
		"A family is reserved as a whole, so that the list does not have to keep up with each program's next key",
		"An empty or absent list admits no caller environment key.",
		"each target path one the artifact declares in its signed `mount_targets` list",
		"An artifact that declares no mount target admits no caller mount",
		"before it reads the payload or any mount artifact, stages anything or contacts Nomad",
		"`invocation.argv` is not bounded by a declaration.",
	)
	assertContainsNone(t, "contracts.md section 5 caller declaration rules", contract,
		"If the manifest runtime interface declares allowed environment keys, provided keys must stay within that set.",
		// Red-team report 19 on PR #74: the list does not cover these
		// languages' keys, only the best-known of them.
		"and the module paths and option keys of Python, Perl, Ruby, Node.js, Java and Git",
	)
	for _, path := range []string{
		".docs/execution_lifecycle/contracts.md",
		".docs/execution_lifecycle/design.md",
		".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md",
		".docs/standing_rules/execution_admission_and_custody.md",
		"PLANS.md",
	} {
		assertContainsNone(t, path, compactText(mustRead(t, path)),
			"empty-environment-allowlist contract",
			"empty environment-allowlist behavior",
			"Empty environment allowlist meaning",
			"current source does not enforce explicit allowlist membership",
			"empty allowlist behavior",
		)
	}
}

// reservedEnvironmentEntriesInSource reads the string-literal keys of
// reservedRuntimeEnvKeys and the elements of reservedRuntimeEnvPrefixes from
// the ES source.
func reservedEnvironmentEntriesInSource(t *testing.T) (map[string]bool, []string) {
	t.Helper()
	path := "es/admission/service.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), path, mustRead(t, path), parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	keys := map[string]bool{}
	var prefixes []string
	for _, decl := range parsed.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for index, name := range value.Names {
				if index >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[index].(*ast.CompositeLit)
				if !ok {
					continue
				}
				switch name.Name {
				case "reservedRuntimeEnvKeys":
					for _, element := range literal.Elts {
						if basic, ok := element.(*ast.KeyValueExpr).Key.(*ast.BasicLit); ok {
							key, err := strconv.Unquote(basic.Value)
							if err != nil {
								t.Fatal(err)
							}
							keys[key] = true
						}
					}
				case "reservedRuntimeEnvPrefixes":
					for _, element := range literal.Elts {
						prefix, err := strconv.Unquote(element.(*ast.BasicLit).Value)
						if err != nil {
							t.Fatal(err)
						}
						prefixes = append(prefixes, prefix)
					}
				}
			}
		}
	}
	if len(keys) == 0 || len(prefixes) == 0 {
		t.Fatalf("did not find the reserved environment entries in %s", path)
	}
	return keys, prefixes
}

func TestLifecycleContractNamesOnlyReservedKeysTheCodeReserves(t *testing.T) {
	keys, prefixes := reservedEnvironmentEntriesInSource(t)
	contract := prepareRequestContract(t)
	start := strings.Index(contract, "Environment keys must not use reserved keys")
	end := strings.Index(contract, "The exact list is `reservedRuntimeEnvKeys`")
	if start < 0 || end < start {
		t.Fatal("contracts.md section 5 must state the reserved keys before naming their source")
	}
	reservedText := contract[start:end]
	for _, prefix := range prefixes {
		covered := false
		for _, other := range prefixes {
			covered = covered || (other != prefix && strings.HasPrefix(prefix, other))
		}
		if !covered && !strings.Contains(reservedText, "`"+prefix+"`") {
			t.Fatalf("contracts.md section 5 does not name the reserved prefix %q", prefix)
		}
	}
	reservesKey := func(key string) bool {
		upper := strings.ToUpper(key)
		if keys[upper] || upper == "EXEC_WORKLOAD_IDENTITY_ENDPOINT" {
			return true
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(upper, prefix) {
				return true
			}
		}
		return false
	}
	named := regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_]*)`").FindAllStringSubmatch(reservedText, -1)
	// Names in the reserved-key text that are not environment keys.
	notKeys := map[string]bool{"initial_badenv_table": true, "usercustomize": true}
	checked := 0
	for _, match := range named {
		name := match[1]
		if notKeys[name] {
			continue
		}
		checked++
		if !reservesKey(name) {
			t.Fatalf("contracts.md section 5 names %q as reserved, but es/admission/service.go does not reserve it", name)
		}
	}
	if checked < 30 {
		t.Fatalf("expected the contract to name at least 30 reserved keys or prefixes, found %d", checked)
	}
}
