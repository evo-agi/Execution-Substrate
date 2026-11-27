package executionsubstrate_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file holds the layout rules that README.md states under "Repo
// Structure". Every service directory has the same shape:
//
//	<svc>/api/        the HTTP adapter
//	<svc>/app/        wiring, used by cmd/<svc> and by in-process tests
//	<svc>/config/     the config file and its loader
//	<svc>/contract/   only when another service's code needs this service's
//	                  types: wire types and their canonical form, and no
//	                  import of any service package
//	<svc>/<domain>/   packages named for what they do
//	<svc>/internal/   packages private to the service
//
// Apart from the repository-wide tests at the repository root, Go code
// lives only in the service directories, cmd/, internal/ and scripts/. Code
// of one service reaches another service only through that service's
// contract package. A test may also start another service
// in-process through its app and config packages. Anything else is listed by
// file in layoutCrossServiceExceptions, with its reason.

// layoutServices are the services of this repository.
var layoutServices = []string{"ags", "ars", "cgs", "egs", "es"}

// layoutRequiredPackages are the packages every service has.
var layoutRequiredPackages = []string{"api", "app", "config"}

// layoutGenericPackageNames say nothing about what a package holds. No
// package directory under a service may have one of these names.
var layoutGenericPackageNames = map[string]bool{
	"common": true, "helper": true, "helpers": true, "lib": true, "misc": true,
	"model": true, "models": true, "shared": true, "types": true, "util": true,
	"utils": true,
}

// layoutOtherTopDirectories are the top-level directories besides the
// services that may hold Go code.
var layoutOtherTopDirectories = map[string]bool{"cmd": true, "internal": true, "scripts": true}

// layoutCommandService names, for each program under cmd/, the one service
// whose packages it may import.
var layoutCommandService = map[string]string{
	"ags":                  "ags",
	"ars":                  "ars",
	"cgs":                  "cgs",
	"egs":                  "egs",
	"es":                   "es",
	"es-runtime-support":   "es",
	"es-workload-api-mock": "es",
}

// layoutImport is one import in one file. Both paths are relative to the
// repository root and the module path.
type layoutImport struct {
	file     string
	imported string
}

// layoutCrossServiceExceptions are the only imports of another service's
// package that the rules above do not allow. Each must still be in use: an
// entry that no file needs any more fails the test, so the list only
// shrinks.
var layoutCrossServiceExceptions = map[layoutImport]string{
	{"ags/app/app_integration_test.go", "ars/index"}:               "reads ARS's on-disk index of an in-process ARS",
	{"ags/app/app_integration_test.go", "ars/store"}:               "reads ARS's on-disk blob store of an in-process ARS",
	{"ags/app/app_integration_test.go", "es/admission"}:            "builds ES prepare requests, whose types live in es/admission",
	{"es/app/app_integration_test.go", "ars/index"}:                "writes ARS's on-disk index for an in-process ARS",
	{"es/app/app_integration_test.go", "ars/store"}:                "writes ARS's on-disk blob store for an in-process ARS",
	{"es/app/submit_integration_test.go", "ars/index"}:             "reads ARS's on-disk index of an in-process ARS",
	{"es/app/submit_integration_test.go", "ars/store"}:             "reads ARS's on-disk blob store of an in-process ARS",
	{"scripts/internal/esconfigcheck/main.go", "es/config"}:        "the ES upgrade script checks a config with ES's own loader",
	{"scripts/remote_alpha_user_identity_test.go", "ags/api"}:      "serves the minted identity through the real AGS handlers",
	{"scripts/remote_alpha_user_identity_test.go", "ags/publish"}:  "stubs the AGS publish service behind those handlers, whose types live in ags/publish",
	{"scripts/remote_alpha_user_identity_test.go", "es/admission"}: "stubs the ES admission service behind the ES handlers, whose types live in es/admission",
	{"scripts/remote_alpha_user_identity_test.go", "es/api"}:       "serves the minted identity through the real ES handlers",
}

// layoutGoFileVisible reports whether the go command builds or tests the
// file at this repository-relative path: a .go file outside testdata and
// outside any file or directory whose name starts with "." or "_".
func layoutGoFileVisible(file string) bool {
	if !strings.HasSuffix(file, ".go") {
		return false
	}
	for _, segment := range strings.Split(file, "/") {
		if segment == "testdata" || strings.HasPrefix(segment, ".") || strings.HasPrefix(segment, "_") {
			return false
		}
	}
	return true
}

// serviceLayoutViolations checks the layout rules against files, which maps
// each Go file's repository-relative path to the import paths it declares.
// It returns one line per violation, sorted.
func serviceLayoutViolations(module string, files map[string][]string, exceptions map[layoutImport]string) []string {
	var violations []string
	isService := make(map[string]bool, len(layoutServices))
	for _, service := range layoutServices {
		isService[service] = true
	}
	topPackages := make(map[string]map[string]bool, len(layoutServices))
	used := make(map[layoutImport]bool, len(exceptions))
	commands := make(map[string]bool)

	for file, imports := range files {
		segments := strings.Split(file, "/")
		owner, command := "", ""
		switch {
		case isService[segments[0]]:
			owner = segments[0]
			if len(segments) < 3 {
				violations = append(violations, fmt.Sprintf("%s: a service directory holds packages, not Go files", file))
				continue
			}
			if topPackages[owner] == nil {
				topPackages[owner] = make(map[string]bool)
			}
			topPackages[owner][segments[1]] = true
			for _, directory := range segments[1 : len(segments)-1] {
				if layoutGenericPackageNames[directory] {
					violations = append(violations, fmt.Sprintf("%s: package directory %q has a generic name; name it for what it holds", file, directory))
				}
			}
		case segments[0] == "cmd" && len(segments) >= 3:
			command = segments[1]
			commands[command] = true
			if _, known := layoutCommandService[command]; !known {
				violations = append(violations, fmt.Sprintf("%s: program cmd/%s is not in layoutCommandService", file, command))
			}
		case len(segments) >= 2 && !layoutOtherTopDirectories[segments[0]]:
			violations = append(violations, fmt.Sprintf("%s: top-level directory %s/ holds Go code but is not a service in layoutServices, cmd/, internal/ or scripts/", file, segments[0]))
		}
		test := strings.HasSuffix(file, "_test.go")
		contract := owner != "" && segments[1] == "contract"

		for _, imported := range imports {
			relative, ok := strings.CutPrefix(imported, module+"/")
			if !ok {
				continue
			}
			target := strings.Split(relative, "/")
			if !isService[target[0]] {
				continue
			}
			if contract && !test {
				violations = append(violations, fmt.Sprintf("%s imports %s: a contract package imports no service package", file, relative))
				continue
			}
			if target[0] == owner {
				continue
			}
			if command != "" {
				if layoutCommandService[command] != target[0] {
					violations = append(violations, fmt.Sprintf("%s imports %s: cmd/%s may import only %s", file, relative, command, layoutCommandService[command]))
				}
				continue
			}
			allowed := false
			if len(target) == 2 {
				switch target[1] {
				case "contract":
					// Shared code in internal/ sits below every service and
					// depends on none of them.
					allowed = test || segments[0] != "internal"
				case "app", "config":
					allowed = test
				}
			}
			if allowed {
				continue
			}
			key := layoutImport{file: file, imported: relative}
			if _, listed := exceptions[key]; listed {
				used[key] = true
				continue
			}
			violations = append(violations, fmt.Sprintf("%s imports %s: another service is reached only through its contract package (and, from a test, its app or config package)", file, relative))
		}
	}

	for command, service := range layoutCommandService {
		if !isService[service] {
			violations = append(violations, fmt.Sprintf("program cmd/%s belongs to %s, which is not in layoutServices", command, service))
		}
	}
	for _, service := range layoutServices {
		for _, required := range layoutRequiredPackages {
			if !topPackages[service][required] {
				violations = append(violations, fmt.Sprintf("%s has no %s/ package", service, required))
			}
		}
		if !commands[service] {
			violations = append(violations, fmt.Sprintf("%s has no cmd/%s program", service, service))
		}
	}
	for key := range exceptions {
		if !used[key] {
			violations = append(violations, fmt.Sprintf("exception %s imports %s is no longer needed; remove it from layoutCrossServiceExceptions", key.file, key.imported))
		}
	}
	sort.Strings(violations)
	return violations
}

// repositoryGoImports parses the imports of every Go file the go command
// sees in this repository.
func repositoryGoImports(t *testing.T) map[string][]string {
	t.Helper()
	files, _ := repositoryFiles(t)
	result := make(map[string][]string)
	for _, file := range files {
		if !layoutGoFileVisible(file) {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports of %s: %v", file, err)
		}
		imports := make([]string, 0, len(parsed.Imports))
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			imports = append(imports, imported)
		}
		result[path.Clean(file)] = imports
	}
	if len(result) < 100 {
		t.Fatalf("found only %d Go files", len(result))
	}
	return result
}

func repositoryModulePath(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(mustRead(t, "go.mod"), "\n") {
		if module, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(module)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}

func TestServiceLayout(t *testing.T) {
	violations := serviceLayoutViolations(repositoryModulePath(t), repositoryGoImports(t), layoutCrossServiceExceptions)
	if len(violations) > 0 {
		t.Fatalf("service layout rules broken (see README.md, Repo Structure, and service_layout_test.go):\n%s", strings.Join(violations, "\n"))
	}
}

// TestServiceLayoutRefusals shows that each rule fails when broken, starting
// from a small repository that keeps every rule.
func TestServiceLayoutRefusals(t *testing.T) {
	const module = "example"
	valid := func() map[string][]string {
		files := map[string][]string{
			"ars/contract/types.go":              nil,
			"ars/index/index.go":                 nil,
			"ars/store/store.go":                 nil,
			"es/admission/service.go":            {"example/ars/contract", "example/es/config", "example/internal/httpx"},
			"es/app/app_test.go":                 {"example/ars/app", "example/ars/config", "example/ars/contract"},
			"es/internal/staticarchive/a.go":     nil,
			"internal/httpx/httpx.go":            nil,
			"internal/callerallowlist/a_test.go": {"example/es/config"},
			"scripts/a_test.go":                  {"example/es/config"},
			"cmd/es-runtime-support/main.go":     {"example/es/runtimehelper"},
		}
		for _, service := range layoutServices {
			for _, required := range layoutRequiredPackages {
				files[service+"/"+required+"/"+required+".go"] = nil
			}
			files["cmd/"+service+"/main.go"] = []string{"example/" + service + "/app", "example/" + service + "/config"}
		}
		files["ars/api/server.go"] = []string{"example/ars/contract", "example/ars/index", "example/ars/store"}
		return files
	}
	if got := serviceLayoutViolations(module, valid(), nil); len(got) != 0 {
		t.Fatalf("the valid repository is refused: %v", got)
	}

	for name, test := range map[string]struct {
		change     func(map[string][]string)
		exceptions map[layoutImport]string
		want       string
	}{
		"production code reaching another service's store": {
			change: func(f map[string][]string) {
				f["es/admission/service.go"] = append(f["es/admission/service.go"], "example/ars/store")
			},
			want: "es/admission/service.go imports ars/store",
		},
		"production code reaching another service's api": {
			change: func(f map[string][]string) {
				f["es/admission/service.go"] = append(f["es/admission/service.go"], "example/ars/api")
			},
			want: "es/admission/service.go imports ars/api",
		},
		"production code reaching another service's app": {
			change: func(f map[string][]string) {
				f["es/admission/service.go"] = append(f["es/admission/service.go"], "example/ars/app")
			},
			want: "es/admission/service.go imports ars/app",
		},
		"production code reaching below another service's contract": {
			change: func(f map[string][]string) {
				f["es/admission/service.go"] = append(f["es/admission/service.go"], "example/ars/contract/v2")
			},
			want: "es/admission/service.go imports ars/contract/v2",
		},
		"a test reaching another service's store": {
			change: func(f map[string][]string) {
				f["es/app/app_test.go"] = append(f["es/app/app_test.go"], "example/ars/store")
			},
			want: "es/app/app_test.go imports ars/store",
		},
		"shared internal code depending on a service": {
			change: func(f map[string][]string) { f["internal/httpx/httpx.go"] = []string{"example/es/contract"} },
			want:   "internal/httpx/httpx.go imports es/contract",
		},
		"code outside the services reaching a service's config": {
			change: func(f map[string][]string) { f["scripts/tool/main.go"] = []string{"example/es/config"} },
			want:   "scripts/tool/main.go imports es/config",
		},
		"a contract package importing its own service's store": {
			change: func(f map[string][]string) { f["ars/contract/types.go"] = []string{"example/ars/store"} },
			want:   "ars/contract/types.go imports ars/store: a contract package",
		},
		"a contract package importing another service's contract": {
			change: func(f map[string][]string) { f["ars/contract/types.go"] = []string{"example/egs/contract"} },
			want:   "ars/contract/types.go imports egs/contract: a contract package",
		},
		"a program importing another service": {
			change: func(f map[string][]string) { f["cmd/es/main.go"] = append(f["cmd/es/main.go"], "example/ars/app") },
			want:   "cmd/es/main.go imports ars/app: cmd/es may import only es",
		},
		"an unknown program": {
			change: func(f map[string][]string) { f["cmd/zz/main.go"] = nil },
			want:   "program cmd/zz is not in layoutCommandService",
		},
		"a generic package name": {
			change: func(f map[string][]string) { f["egs/model/trustmodel.go"] = nil },
			want:   `package directory "model" has a generic name`,
		},
		"a generic name deeper down": {
			change: func(f map[string][]string) { f["es/admission/internal/util/a.go"] = nil },
			want:   `package directory "util" has a generic name`,
		},
		"a Go file directly in a service directory": {
			change: func(f map[string][]string) { f["cgs/main.go"] = nil },
			want:   "cgs/main.go: a service directory holds packages",
		},
		"a service without a config package": {
			change: func(f map[string][]string) { delete(f, "cgs/config/config.go") },
			want:   "cgs has no config/ package",
		},
		"a service without a program": {
			change: func(f map[string][]string) { delete(f, "cmd/egs/main.go") },
			want:   "egs has no cmd/egs program",
		},
		"an exception nothing needs any more": {
			change:     func(map[string][]string) {},
			exceptions: map[layoutImport]string{{"es/app/app_test.go", "ars/store"}: "gone"},
			want:       "exception es/app/app_test.go imports ars/store is no longer needed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			files := valid()
			test.change(files)
			got := serviceLayoutViolations(module, files, test.exceptions)
			found := false
			for _, violation := range got {
				found = found || strings.Contains(violation, test.want)
			}
			if !found {
				t.Fatalf("got %q, want a violation containing %q", got, test.want)
			}
		})
	}

	// Each entry of the rule lists is held here twice: the lists must equal
	// these, and every entry is shown to refuse what it names. Dropping an
	// entry from a list, which would let a rule lapse without failing any
	// other test, fails here.
	wantServices := []string{"ags", "ars", "cgs", "egs", "es"}
	wantRequired := []string{"api", "app", "config"}
	wantGeneric := []string{"common", "helper", "helpers", "lib", "misc", "model", "models", "shared", "types", "util", "utils"}
	gotGeneric := make([]string, 0, len(layoutGenericPackageNames))
	for name := range layoutGenericPackageNames {
		gotGeneric = append(gotGeneric, name)
	}
	sort.Strings(gotGeneric)
	for _, list := range []struct {
		name      string
		got, want []string
	}{
		{"layoutServices", layoutServices, wantServices},
		{"layoutRequiredPackages", layoutRequiredPackages, wantRequired},
		{"layoutGenericPackageNames", gotGeneric, wantGeneric},
	} {
		if strings.Join(list.got, " ") != strings.Join(list.want, " ") {
			t.Fatalf("%s is %q, want %q: change the rule and this test together", list.name, list.got, list.want)
		}
	}
	refuses := func(t *testing.T, files map[string][]string, want string) {
		t.Helper()
		got := serviceLayoutViolations(module, files, nil)
		for _, violation := range got {
			if strings.Contains(violation, want) {
				return
			}
		}
		t.Fatalf("got %q, want a violation containing %q", got, want)
	}
	for _, service := range wantServices {
		other := "es"
		if service == "es" {
			other = "ars"
		}
		t.Run("service "+service+" reached from production code", func(t *testing.T) {
			files := valid()
			files[service+"/store/store.go"] = nil
			files[other+"/zz/zz.go"] = []string{"example/" + service + "/store"}
			refuses(t, files, other+"/zz/zz.go imports "+service+"/store: another service")
		})
		t.Run("service "+service+" reached from a test", func(t *testing.T) {
			files := valid()
			files[service+"/store/store.go"] = nil
			files[other+"/zz/zz_test.go"] = []string{"example/" + service + "/store"}
			refuses(t, files, other+"/zz/zz_test.go imports "+service+"/store: another service")
		})
		t.Run("service "+service+" with a generic package name", func(t *testing.T) {
			files := valid()
			files[service+"/util/util.go"] = nil
			refuses(t, files, service+`/util/util.go: package directory "util" has a generic name`)
		})
		for _, required := range wantRequired {
			t.Run("service "+service+" without "+required, func(t *testing.T) {
				files := valid()
				for file := range files {
					if strings.HasPrefix(file, service+"/"+required+"/") {
						delete(files, file)
					}
				}
				refuses(t, files, service+" has no "+required+"/ package")
			})
		}
	}
	for _, name := range wantGeneric {
		t.Run("generic name "+name, func(t *testing.T) {
			files := valid()
			files["egs/"+name+"/a.go"] = nil
			refuses(t, files, fmt.Sprintf("package directory %q has a generic name", name))
		})
	}
	t.Run("a top-level directory that is not a service", func(t *testing.T) {
		files := valid()
		files["pkg/thing/thing.go"] = nil
		refuses(t, files, "pkg/thing/thing.go: top-level directory pkg/ holds Go code")
	})
	t.Run("a Go file directly in a top-level directory that is not a service", func(t *testing.T) {
		files := valid()
		files["pkg/leak.go"] = nil
		refuses(t, files, "pkg/leak.go: top-level directory pkg/ holds Go code")
	})
	t.Run("a test file at the repository root is allowed", func(t *testing.T) {
		files := valid()
		files["zz_docs_contract_test.go"] = []string{"example/es/config"}
		if got := serviceLayoutViolations(module, files, nil); len(got) != 0 {
			t.Fatalf("a root test file is refused: %v", got)
		}
	})
	t.Run("a program of a service that is not listed", func(t *testing.T) {
		saved := layoutCommandService["es-workload-api-mock"]
		layoutCommandService["es-workload-api-mock"] = "zz"
		defer func() { layoutCommandService["es-workload-api-mock"] = saved }()
		refuses(t, valid(), "program cmd/es-workload-api-mock belongs to zz, which is not in layoutServices")
	})

	// A listed exception allows exactly its own file and import.
	files := valid()
	files["es/app/app_test.go"] = append(files["es/app/app_test.go"], "example/ars/store")
	exceptions := map[layoutImport]string{{"es/app/app_test.go", "ars/store"}: "reason"}
	if got := serviceLayoutViolations(module, files, exceptions); len(got) != 0 {
		t.Fatalf("a listed exception is refused: %v", got)
	}
	files["es/app/other_test.go"] = []string{"example/ars/store"}
	if got := serviceLayoutViolations(module, files, exceptions); len(got) != 1 || !strings.Contains(got[0], "es/app/other_test.go imports ars/store") {
		t.Fatalf("an exception for one file allowed another: %v", got)
	}
}

func TestLayoutGoFileVisible(t *testing.T) {
	for file, want := range map[string]bool{
		"es/admission/service.go":                   true,
		"es/admission/service_test.go":              true,
		"es/admission/testdata/fixture.go":          false,
		"es/_x/a.go":                                false,
		"es/.x/a.go":                                false,
		"es/admission/_scratch.go":                  false,
		"es/admission/README.md":                    false,
		".examples/runtime_identity_reference/a.go": false,
	} {
		if got := layoutGoFileVisible(file); got != want {
			t.Errorf("layoutGoFileVisible(%q) = %v, want %v", file, got, want)
		}
	}
}
