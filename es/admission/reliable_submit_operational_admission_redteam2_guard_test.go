package admission

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

// RT2-1, found and written by the red-team of the combined change of PR #12
// and its fix PR #13 (report 13-red-team.md, section 4) and adopted as a
// permanent test. It failed at bff8dda, 36 of 36 subtests.
//
// modernc.org/libc is already in the module graph as an indirect
// requirement of the SQLite driver. It exports, as plain Go functions, the C
// library's memory primitives (Xmemset, Xmemcpy and the rest) that write any
// address of the process. modernc.org/sqlite/lib exports the transpiled SQLite
// C API with the same kind of raw address arguments, and modernc.org/memory
// hands out raw addresses. A production file that imports one of them can
// clear the latches of the admission state, or refresh its confirmation,
// without reflect, unsafe, cgo or any operating-system call. Unlike a write
// through the operating system, here the import itself names the facility, so
// the import inventory can and must see it. No production file imports any of
// them today; only modernc.org/sqlite itself is imported, by the store.
//
// google.golang.org/protobuf/runtime/protoimpl, from a module that gRPC
// already brings into the build list, exports Pointer, a type whose
// underlying type is unsafe.Pointer. A conversion through it turns an integer
// address into a pointer of any type with no unsafe import (found by the PR
// #13 writer after the red-team). The import inventory now holds every
// dependency package that is not on the reviewed list, so all five fail it.
var redTeamRawMemoryDependencies = []string{
	"modernc.org/libc",
	"modernc.org/libc/sys/types",
	"modernc.org/memory",
	"modernc.org/sqlite/lib",
	"google.golang.org/protobuf/runtime/protoimpl",
}

func TestRedTeamPR12CombinedRawMemoryDependencyImportIsInventoried(t *testing.T) {
	_, sources := repositoryProductionListings(t, repositoryRootForAdmissionGuard(t))
	if len(sources) < 100 {
		t.Fatalf("read only %d production sources", len(sources))
	}
	base, err := operationalGuardImportPins(sources)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range redTeamRawMemoryDependencies {
		for _, form := range []string{"plain", "blank", "renamed"} {
			for _, added := range []string{"es/admission/added.go", "es/app/added.go", "es/app/testdata/added/added.go"} {
				t.Run(fmt.Sprintf("%s %s in %s", form, imported, filepath.Dir(added)), func(t *testing.T) {
					var spec string
					switch form {
					case "plain":
						spec = fmt.Sprintf("import %q\n", imported)
					case "blank":
						spec = fmt.Sprintf("import _ %q\n", imported)
					default:
						spec = fmt.Sprintf("import hidden %q\n", imported)
					}
					mutated := make(map[string]string, len(sources)+1)
					for file, source := range sources {
						mutated[file] = source
					}
					mutated[added] = "package added\n" + spec
					got, err := operationalGuardImportPins(mutated)
					if err != nil {
						t.Fatal(err)
					}
					if reflect.DeepEqual(got, base) {
						t.Fatalf("a production import of %s passed the import inventory", imported)
					}
				})
			}
		}
	}
}
