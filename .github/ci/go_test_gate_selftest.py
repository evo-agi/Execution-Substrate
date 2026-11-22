#!/usr/bin/env python3
"""Checks of go_test_gate.py against small throwaway Go modules.

Run from anywhere:

    python3 -I -B .github/ci/go_test_gate_selftest.py

Needs the go command. Each check writes a module named "synth" into a
temporary directory, runs the gate there exactly as the workflow runs it, and
compares the exit status and the set of test functions that really executed.
Every generated test function records that it ran by creating a marker file,
so "skipped" and "ran" are observed, not read from go test output.
"""

import os
import subprocess
import sys
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "go_test_gate.py")

PASS = "pass"
FAIL = "fail"

PREAMBLE = """package %(package)s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ran(t *testing.T) {
	t.Helper()
	name := "%(mark)s." + strings.ReplaceAll(t.Name(), "/", "__")
	if err := os.WriteFile(filepath.Join(os.Getenv("GATE_SELFTEST_MARKS"), name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
"""

FUNCTION = {
    PASS: """
func %(name)s(t *testing.T) {
	ran(t)
}
""",
    FAIL: """
func %(name)s(t *testing.T) {
	ran(t)
	t.Fatal("deliberate failure")
}
""",
}

FAILING_SUBTEST = """
func %(parent)s(t *testing.T) {
	ran(t)
	t.Run("%(child)s", func(t *testing.T) {
		ran(t)
		t.Fatal("deliberate failure")
	})
}
"""

# A module with one listed failing test, portable tests around it, the same
# test name passing in a second package, and a package without tests.
BASE = {
    "a": {"TestListed": FAIL, "TestPortable": PASS},
    "b": {"TestListed": PASS, "TestOther": PASS},
    "c": {},
}
BASE_RAN = {"synth/a.TestPortable", "synth/b.TestListed", "synth/b.TestOther"}


def import_path(directory):
    return "synth" if directory == "" else "synth/" + directory


def write_module(root, packages, extra_source=None):
    """Write module "synth". packages maps a directory to {test name: outcome}."""
    with open(os.path.join(root, "go.mod"), "w") as handle:
        handle.write("module synth\n\ngo 1.21\n")
    for directory, tests in packages.items():
        target = os.path.join(root, directory)
        os.makedirs(target, exist_ok=True)
        package = "synth" if directory == "" else os.path.basename(directory)
        with open(os.path.join(target, "code.go"), "w") as handle:
            handle.write("package %s\n" % package)
        if not tests and not (extra_source and directory in extra_source):
            continue
        mark = import_path(directory).replace("/", "__")
        source = PREAMBLE % {"package": package, "mark": mark}
        for name, outcome in tests.items():
            source += FUNCTION[outcome] % {"name": name}
        if extra_source and directory in extra_source:
            source += extra_source[directory]
        with open(os.path.join(target, "code_test.go"), "w") as handle:
            handle.write(source)


def run_gate(mode, packages, listing, extra_source=None, arguments=None):
    """Run the gate in a new module. Return (exit status, tests that ran, output)."""
    with tempfile.TemporaryDirectory() as root:
        module = os.path.join(root, "module")
        marks = os.path.join(root, "marks")
        os.makedirs(module)
        os.makedirs(marks)
        write_module(module, packages, extra_source)
        list_path = os.path.join(root, "list.txt")
        with open(list_path, "wb") as handle:
            handle.write(listing if isinstance(listing, bytes) else listing.encode("utf-8"))
        environment = dict(os.environ)
        environment["GATE_SELFTEST_MARKS"] = marks
        if arguments is None:
            arguments = [mode, list_path]
        done = subprocess.run(
            [sys.executable, "-I", "-B", GATE] + arguments,
            cwd=module,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        ran = {name.replace("__", "/") for name in os.listdir(marks)}
        return done.returncode, ran, done.stdout.decode("utf-8", "replace")


class GateScopesEachEntryToItsPackage(unittest.TestCase):
    def check(self, packages, listing, status, ran, extra_source=None):
        got_status, got_ran, output = run_gate("gate", packages, listing, extra_source)
        self.assertEqual(got_status, status, output)
        self.assertEqual(got_ran, ran, output)
        return output

    def test_skips_only_the_listed_test_in_the_listed_package(self):
        output = self.check(BASE, "synth/a TestListed\n", 0, BASE_RAN)
        self.assertIn("test gate passed: 3 packages", output)

    def test_same_name_failing_in_an_unlisted_package_fails_the_gate(self):
        # The regression the audit asked for: the old gate skipped the name in
        # every package, so this failing test never ran and the gate passed.
        packages = {"a": {"TestListed": FAIL}, "b": {"TestListed": FAIL}}
        output = self.check(packages, "synth/a TestListed\n", 1, {"synth/b.TestListed"})
        self.assertIn("--- FAIL: TestListed", output)
        self.assertIn("FAIL\tsynth/b", output)

    def test_entries_of_one_listed_package_do_not_reach_another_listed_package(self):
        listing = "synth/a TestA\nsynth/b TestB\n"
        failing = {"a": {"TestA": FAIL}, "b": {"TestB": FAIL, "TestA": FAIL}}
        self.check(failing, listing, 1, {"synth/b.TestA"})
        passing = {"a": {"TestA": FAIL}, "b": {"TestB": FAIL, "TestA": PASS}}
        self.check(passing, listing, 0, {"synth/b.TestA"})

    def test_root_package_entry_does_not_reach_a_subpackage(self):
        listing = "synth TestListed\n"
        failing = {"": {"TestListed": FAIL, "TestRoot": PASS}, "a": {"TestListed": FAIL}}
        self.check(failing, listing, 1, {"synth.TestRoot", "synth/a.TestListed"})
        passing = {"": {"TestListed": FAIL, "TestRoot": PASS}, "a": {"TestListed": PASS}}
        self.check(passing, listing, 0, {"synth.TestRoot", "synth/a.TestListed"})

    def test_subpackage_entry_does_not_reach_the_root_package(self):
        packages = {"": {"TestListed": FAIL}, "a": {"TestListed": FAIL}}
        self.check(packages, "synth/a TestListed\n", 1, {"synth.TestListed"})

    def test_module_whose_only_package_has_entries(self):
        packages = {"": {"TestListed": FAIL, "TestRoot": PASS}}
        self.check(packages, "synth TestListed\n", 0, {"synth.TestRoot"})

    def test_unlisted_failure_in_a_listed_package_fails_the_gate(self):
        packages = {"a": {"TestListed": FAIL, "TestPortable": FAIL}, "b": {"TestOther": PASS}}
        self.check(packages, "synth/a TestListed\n", 1, {"synth/a.TestPortable", "synth/b.TestOther"})

    def test_names_that_only_resemble_an_entry_are_not_skipped(self):
        for name in ("TestListedV2", "TestXTestListed", "TestLISTED", "TestListe"):
            with self.subTest(name=name):
                packages = {"a": {"TestListed": FAIL, name: FAIL}}
                self.check(packages, "synth/a TestListed\n", 1, {"synth/a." + name})

    def test_subtest_named_like_an_entry_is_not_skipped(self):
        extra = {"a": FAILING_SUBTEST % {"parent": "TestParent", "child": "TestListed"}}
        packages = {"a": {"TestListed": FAIL}}
        self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/a.TestParent", "synth/a.TestParent/TestListed"},
            extra_source=extra,
        )

    def test_compile_error_fails_the_gate(self):
        broken = "\nfunc TestBroken(t *testing.T) { undefined() }\n"
        for directory in ("a", "b"):
            with self.subTest(package=directory):
                status, _, output = run_gate(
                    "gate", BASE, "synth/a TestListed\n", extra_source={directory: broken}
                )
                self.assertEqual(status, 1, output)

    def test_list_without_entries_skips_nothing(self):
        for listing in ("", "# nothing is environment-only\n\n"):
            with self.subTest(listing=listing):
                self.check(BASE, listing, 1, BASE_RAN | {"synth/a.TestListed"})
        clean = {"a": {"TestPortable": PASS}, "b": {"TestOther": PASS}}
        self.check(clean, "", 0, {"synth/a.TestPortable", "synth/b.TestOther"})


class GateRefusesAListItCannotTakeLiterally(unittest.TestCase):
    def refused(self, listing, before_any_go_command=False):
        status, ran, output = run_gate("gate", BASE, listing)
        self.assertEqual(status, 2, output)
        self.assertEqual(ran, set(), output)
        self.assertIn("::error::test gate list: ", output)
        if before_any_go_command:
            # Refused on its text alone, not because no test has that name.
            self.assertNotIn("+ go ", output)

    def test_entries_that_are_not_one_plain_package_and_test_name(self):
        lines = (
            "synth/a Test.*",
            "synth/a TestList.*",
            "synth/a TestFoo|TestListed",
            "synth/a ^TestListed$",
            "synth/a (TestListed)",
            "synth/a TestListe[d]",
            "synth/a TestListed/sub",
            "synth/a Listed",
            "synth/a testListed",
            "synth/a TestListed ",
            " synth/a TestListed",
            "synth/a  TestListed",
            "synth/a\tTestListed",
            "synth/a TestListed TestPortable",
            "synth/a TestListed # reason",
            "synth/a",
            "TestListed",
            "./a TestListed",
            "synth/a TestListed\r",
            " # indented comment",
            " ",
            "synth/a TestListed ",
        )
        for line in lines:
            with self.subTest(line=line):
                self.refused("# header\n" + line + "\n", before_any_go_command=True)
        with self.subTest(line="invalid UTF-8"):
            self.refused(b"synth/a TestListed\n# \xff\n", before_any_go_command=True)

    def test_package_patterns_and_unknown_packages(self):
        for package in ("synth/...", "synth/zzz", "synth/a/..", "other/a", "a"):
            with self.subTest(package=package):
                self.refused(package + " TestListed\n")

    def test_entry_whose_test_is_not_defined_in_that_package(self):
        for line in ("synth/a TestMissing", "synth/b TestPortable", "synth/c TestListed"):
            with self.subTest(line=line):
                self.refused(line + "\n")

    def test_repeated_entry(self):
        self.refused("synth/a TestListed\nsynth/a TestListed\n", before_any_go_command=True)

    def test_bad_command_lines(self):
        for arguments in ([], ["gate"], ["check", "list.txt"], ["gate", "list.txt", "extra"]):
            with self.subTest(arguments=arguments):
                status, ran, output = run_gate("gate", BASE, "", arguments=arguments)
                self.assertEqual(status, 2, output)
                self.assertEqual(ran, set(), output)

    def test_missing_list_file(self):
        status, ran, output = run_gate("gate", BASE, "", arguments=["gate", "no-such-list.txt"])
        self.assertEqual(status, 2, output)
        self.assertEqual(ran, set(), output)


class EnvironmentOnlyRunsExactlyTheEntries(unittest.TestCase):
    def test_runs_only_the_listed_test_in_the_listed_package(self):
        status, ran, output = run_gate("environment-only", BASE, "synth/a TestListed\n")
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/a.TestListed"}, output)

    def test_reports_success_when_the_listed_test_passes(self):
        status, ran, output = run_gate("environment-only", BASE, "synth/b TestListed\n")
        self.assertEqual(status, 0, output)
        self.assertEqual(ran, {"synth/b.TestListed"}, output)

    def test_refuses_a_bad_list(self):
        for listing in ("synth/a Test.*\n", "synth/zzz TestListed\n"):
            with self.subTest(listing=listing):
                status, ran, output = run_gate("environment-only", BASE, listing)
                self.assertEqual(status, 2, output)
                self.assertEqual(ran, set(), output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
