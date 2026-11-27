package executionsubstrate_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
		// Re-check 25 Opus N1: the sentences on keys left open follow the one
		// that calls the list a backstop.
		"It is a backstop for a publisher's mistake, not the boundary: no list can name every variable every program reads. The boundary is the allowlist in the next rule. Some keys of these kinds stay open on purpose.",
		"They do not include every such key; the families below add more",
		"A family is reserved as a whole, so that the list does not have to keep up with each program's next key",
		"every key that ends in `INSECURE_SKIP_VERIFY`",
		// Report 24 on PR #74: why LANGUAGE is reserved and LANG and LC_ALL
		// are not.
		"skips a `LANGUAGE` entry that holds a path only in set-user-ID programs",
		"`LANG` and `LC_ALL` stay open: glibc refuses a locale name that climbs out of the locale directory and looks a name up only under that directory unless `LOCPATH`, which is reserved, is set (`locale/findlocale.c`), so they select only installed locales.",
		// Re-checks 25 and 27 on PR #74: the Go and gcc sentences name their
		// sources, and say which keys of those kinds stay open and why.
		"every such key `go help environment` lists in Go 1.26.5",
		"the GNU C compiler's keys that choose the programs it runs, the headers and libraries it builds with, extra options, or a file it writes with text the caller chooses (`GCC_EXEC_PREFIX`, `COMPILER_PATH`, `LIBRARY_PATH`, `LPATH`, `CPATH`, `C_INCLUDE_PATH`, `CPLUS_INCLUDE_PATH`, `OBJC_INCLUDE_PATH`, `OBJCPLUS_INCLUDE_PATH`, `MSP430_GCC_INCLUDE_DIR`, `GCC_COMPARE_DEBUG`, `DEPENDENCIES_OUTPUT`, `SUNPRO_DEPENDENCIES`, `MAKE`, which names the program gcc's link-time optimizer runs for a parallel link, and `CXX_MODULE_MAPPER`, whose `|program` form names a program the C++ compiler starts: every such key a GCC program reads that the GCC 14.2.0 manual, `gcc/doc/gcc.texi` and the files it includes, names in any section, not only in its section on environment variables, and the two that gcc's driver and preprocessor read and the manual leaves out, `LPATH` and `OBJCPLUS_INCLUDE_PATH`);",
		"`GOOS`, `GOARCH` and the other target keys, `GO111MODULE` and `GOFIPS140` choose only among code the artifact or the Go toolchain already holds.",
		"gcc's `SOURCE_DATE_EPOCH` and `GCC_EXTRA_DIAGNOSTIC_OUTPUT` change only a timestamp and the text of its diagnostics.",
		"The gcc keys above are the ones a GCC program reads: keys the GCC manual names that a program built with gcc reads when it runs, such as the sanitizer runtime's `ASAN_OPTIONS` and the coverage runtime's `GCOV_PREFIX`, are outside that class and are not reserved.",
		// Re-check 25 on PR #74: pkg-config's search keys are reserved with
		// its program, as a family.
		"`PKG_CONFIG` (the pkg-config program a cgo build runs, and the keys that choose the `.pc` files that give it flags and libraries)",
		// Audit 21 and re-check 23 on PR #74: what sudo 1.9.16p2 does not
		// hold is credited to its development branch, by name.
		"the entries sudo's development branch adds to that table after 1.9.16p2 (read on 2026-11-26): `_JAVA_OPTIONS`, `CLASSPATH`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `NODE_PATH`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*` and `GCONV_PATH`, which the glibc list above already holds.",
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
// reservedRuntimeEnvKeys and the elements of reservedRuntimeEnvPrefixes and
// reservedRuntimeEnvSuffixes from the ES source.
func reservedEnvironmentEntriesInSource(t *testing.T) (map[string]bool, []string, []string) {
	t.Helper()
	path := "es/admission/service.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), path, mustRead(t, path), parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	keys := map[string]bool{}
	var prefixes, suffixes []string
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
				case "reservedRuntimeEnvPrefixes", "reservedRuntimeEnvSuffixes":
					for _, element := range literal.Elts {
						entry, err := strconv.Unquote(element.(*ast.BasicLit).Value)
						if err != nil {
							t.Fatal(err)
						}
						if name.Name == "reservedRuntimeEnvPrefixes" {
							prefixes = append(prefixes, entry)
						} else {
							suffixes = append(suffixes, entry)
						}
					}
				}
			}
		}
	}
	if len(keys) == 0 || len(prefixes) == 0 || len(suffixes) == 0 {
		t.Fatalf("did not find the reserved environment entries in %s", path)
	}
	return keys, prefixes, suffixes
}

// reservedEnvironmentKeyMatcher reports whether es/admission/service.go
// reserves a key, from the entries reservedEnvironmentEntriesInSource reads.
func reservedEnvironmentKeyMatcher(keys map[string]bool, prefixes, suffixes []string) func(string) bool {
	return func(key string) bool {
		// isReservedRuntimeEnvKey trims white space and folds only the ASCII
		// letters; read a key the same way.
		upper := strings.Map(func(r rune) rune {
			if 'a' <= r && r <= 'z' {
				return r - ('a' - 'A')
			}
			return r
		}, strings.TrimSpace(key))
		if keys[upper] || upper == "EXEC_WORKLOAD_IDENTITY_ENDPOINT" {
			return true
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(upper, prefix) {
				return true
			}
		}
		for _, suffix := range suffixes {
			if strings.HasSuffix(upper, suffix) {
				return true
			}
		}
		return false
	}
}

func TestLifecycleContractNamesOnlyReservedKeysTheCodeReserves(t *testing.T) {
	keys, prefixes, suffixes := reservedEnvironmentEntriesInSource(t)
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
	for _, suffix := range suffixes {
		if !strings.Contains(reservedText, "ends in `"+suffix+"`") {
			t.Fatalf("contracts.md section 5 does not name the reserved suffix %q", suffix)
		}
	}
	reservesKey := reservedEnvironmentKeyMatcher(keys, prefixes, suffixes)
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

// Re-check 25 on PR #74: a runbook or example that declares a reserved key
// publishes fine, because AGS signs the declaration as given, and its caller
// is refused only at submit. This keeps the repository's own publish requests
// free of reserved keys. Re-check 27: the scan reads an entry as a publish
// request carries it (JSON escapes decoded; ES then trims and folds it, as the
// matcher does), reads single-quoted (Python) lists too, and fails on a
// declaration in a spelling it cannot read.
func TestRunbooksAndExamplesDeclareNoReservedEnvironmentKey(t *testing.T) {
	reservesKey := reservedEnvironmentKeyMatcher(reservedEnvironmentEntriesInSource(t))
	// The matcher must read a declared entry as ES does: trimmed, with only
	// the ASCII letters folded (U+017F is not the letter S to ES).
	for _, spelling := range []string{" LD_PRELOAD", "ld_preload\t", "Shell"} {
		if !reservesKey(spelling) {
			t.Fatalf("the matcher does not reserve %q, which ES reserves", spelling)
		}
	}
	if reservesKey("\u017fhell") {
		t.Fatal("the matcher folds a non-ASCII letter, which ES does not")
	}
	declaration := regexp.MustCompile(`["']environment_variables["']\s*:\s*\[([^\]]*)\]`)
	// Any spelling of a declaration: quoted or not, escaped quotes, ":" or "=".
	anyDeclaration := regexp.MustCompile(`environment_variables[\\"']*\s*[:=]\s*\[`)
	entry := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`)
	declared := map[string][]string{}
	lists := map[string]int{}
	for _, root := range []string{".runbooks", ".examples", ".docs", "scripts"} {
		err := filepath.WalkDir(root, func(path string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if dirEntry.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".gz", ".tgz", ".tar", ".png", ".svg", ".pdf":
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found := declaration.FindAllStringSubmatch(string(data), -1)
			if spelled := len(anyDeclaration.FindAllStringIndex(string(data), -1)); spelled != len(found) {
				t.Errorf("%s holds %d environment_variables declarations, but the scan reads %d; teach the scan that spelling", path, spelled, len(found))
			}
			lists[root] += len(found)
			for _, list := range found {
				for _, match := range entry.FindAllStringSubmatch(list[1], -1) {
					key := declaredEnvironmentEntry(match)
					declared[key] = append(declared[key], path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	// The scan must see the declarations it guards: in each root that holds
	// some today, and the known keys.
	for _, root := range []string{".runbooks", ".examples", "scripts"} {
		if lists[root] == 0 {
			t.Fatalf("found no environment_variables declaration in %s", root)
		}
	}
	for _, key := range []string{"APP_MODE", "WORKLOAD_VAULT_SECRET_PATH", "REFERENCE_IDENTITY_URL"} {
		if len(declared[key]) == 0 {
			t.Fatalf("did not find the declaration of %s in the runbooks and examples", key)
		}
	}
	var refused []string
	for key, paths := range declared {
		if reservesKey(key) {
			refused = append(refused, strconv.Quote(key)+" in "+strings.Join(paths, ", "))
		}
	}
	sort.Strings(refused)
	if len(refused) > 0 {
		t.Fatalf("a runbook or example declares a reserved environment key, which ES refuses from every caller: %s", strings.Join(refused, "; "))
	}
}

// declaredEnvironmentEntry decodes one quoted list entry that the guard above
// matched: a double-quoted entry as JSON, the form a publish request carries,
// and a single-quoted one as a Python string, whose escapes a key could use
// Go's string syntax also reads.
func declaredEnvironmentEntry(match []string) string {
	if strings.HasPrefix(match[0], `"`) {
		var decoded string
		if json.Unmarshal([]byte(match[0]), &decoded) == nil {
			return decoded
		}
		if decoded, err := strconv.Unquote(match[0]); err == nil {
			return decoded
		}
		return match[1]
	}
	body := strings.ReplaceAll(strings.ReplaceAll(match[2], `\'`, `'`), `"`, `\"`)
	if decoded, err := strconv.Unquote(`"` + body + `"`); err == nil {
		return decoded
	}
	return match[2]
}
