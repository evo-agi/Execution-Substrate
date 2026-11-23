// Package testtmpdir runs the tests of a package under a temporary directory
// whose path holds no symbolic link. It is test support: only test files of
// this module import it, and no command or service links it.
//
// ES refuses a symbolic link in any component of the staging and results
// roots, key files, support binary and store roots it is configured with,
// and so do the reliable-submit store and the Remote Alpha scripts. On
// macOS the default temporary directory, /var/folders/..., lies behind the
// symbolic link /var -> private/var, and /tmp is the symbolic link
// /tmp -> private/tmp. A test that gives ES a path below t.TempDir() there
// tests that refusal instead of what it is named for: a test that expects
// success fails, and a test that expects a refusal can pass for the wrong
// reason. Main gives every test of a test binary, and every process those
// tests start, the same directory by its physical path.
//
// The rule and its guard are described in
// .docs/system_overview/capability_probing.md, section "Test Harness Use".
package testtmpdir

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ExitResolveFailed is the exit status of a test binary whose temporary
// directory cannot be resolved. No test runs then.
const ExitResolveFailed = 2

// Main resolves the temporary directory, then runs the tests and returns
// their exit status. Every package of the module that has tests calls it
// from its TestMain, in exactly this form:
//
//	func TestMain(m *testing.M) { os.Exit(testtmpdir.Main(m)) }
//
// When the directory cannot be resolved, Main runs no test, writes the
// reason to standard error and returns ExitResolveFailed.
func Main(m *testing.M) int {
	if err := Resolve(); err != nil {
		fmt.Fprintf(os.Stderr, "testtmpdir: %v\n", err)
		return ExitResolveFailed
	}
	return m.Run()
}

// Resolve makes os.TempDir name the temporary directory by its physical
// path. When the path that os.TempDir returns goes through a symbolic link,
// Resolve sets TMPDIR to the physical path of the same directory. When the
// path is already physical, Resolve changes nothing, so a host whose
// temporary directory has no symbolic link runs exactly as before, an unset
// TMPDIR included.
//
// Resolve fails when the path is not absolute, does not name a directory,
// cannot be resolved, or resolves to a path that does not name the same
// directory or still holds a symbolic link.
func Resolve() error {
	given := os.TempDir()
	if !filepath.IsAbs(given) {
		return fmt.Errorf("temporary directory %q is not an absolute path", given)
	}
	givenInfo, err := os.Stat(given)
	if err != nil {
		return fmt.Errorf("temporary directory %q: %w", given, err)
	}
	if !givenInfo.IsDir() {
		return fmt.Errorf("temporary directory %q is not a directory", given)
	}
	physical, err := filepath.EvalSymlinks(given)
	if err != nil {
		return fmt.Errorf("resolve temporary directory %q: %w", given, err)
	}
	if physical == filepath.Clean(given) {
		return nil
	}
	physicalInfo, err := os.Stat(physical)
	if err != nil {
		return fmt.Errorf("resolved temporary directory %q of %q: %w", physical, given, err)
	}
	if !os.SameFile(givenInfo, physicalInfo) {
		return fmt.Errorf("resolved temporary directory %q is not the directory %q", physical, given)
	}
	again, err := filepath.EvalSymlinks(physical)
	if err != nil {
		return fmt.Errorf("resolve temporary directory %q again: %w", physical, err)
	}
	if again != physical {
		return fmt.Errorf("resolved temporary directory %q of %q still holds a symbolic link", physical, given)
	}
	if err := os.Setenv("TMPDIR", physical); err != nil {
		return fmt.Errorf("set TMPDIR to %q: %w", physical, err)
	}
	if got := os.TempDir(); got != physical {
		return fmt.Errorf("temporary directory is %q after TMPDIR was set to %q", got, physical)
	}
	return nil
}
