#!/usr/bin/env python3
"""Checks of go_test_gate.py against small throwaway Go modules.

Run from anywhere:

    python3 -I -B .github/ci/go_test_gate_selftest.py

Needs the go command. Each check writes a module named "synth" into a
temporary directory, runs the gate there exactly as the workflow runs it, and
compares the exit status and the set of test functions that really executed.
Every generated test function records that it ran by creating a marker file,
so "skipped" and "ran" are observed, not read from go test output.

The last group reads ../workflows/go.yml beside this file. It holds that file
as a whole by its SHA-256, so every edit of the workflow has to change the
value in this file in the same change, and it checks some properties of the
workflow that the gate's guarantees depend on.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "go_test_gate.py")
WORKFLOW = os.path.join(HERE, os.pardir, "workflows", "go.yml")
# SHA-256 of that file as it was last reviewed. See
# test_the_workflow_file_is_the_text_that_was_reviewed.
WORKFLOW_SHA256 = "3bdcd062217b2373a2fda21d92fd678f44e51ad3df466ef84a466be26a5567b5"

PASS = "pass"
FAIL = "fail"
SKIP = "skip"
PANIC = "panic"
EXIT = "exit"

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

# What a generated test or subtest does after it has recorded that it ran.
BODY = {
    PASS: "",
    FAIL: 't.Fatal("deliberate failure")\n',
    SKIP: 't.Skip("deliberate skip")\n',
    PANIC: 'panic("deliberate panic")\n',
    EXIT: "os.Exit(3)\n",
}

# A test that leaves its marker without the os package. go test records the
# files and environment variables a test reads through that package and
# reruns the test when one of them changes. This test gives it no such
# reason, so only -count=1 makes it run again.
QUIET = """package %(package)s

import (
	"syscall"
	"testing"
)

func TestQuiet(t *testing.T) {
	directory, _ := syscall.Getenv("GATE_SELFTEST_MARKS")
	descriptor, err := syscall.Open(directory+"/%(mark)s.TestQuiet", syscall.O_CREAT|syscall.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(descriptor)
}
"""

# A test binary that lists its tests and runs none of them.
RUNS_NOTHING = """package a

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if flag.Lookup("test.list").Value.String() != "" {
		os.Exit(m.Run())
	}
	os.Exit(0)
}
"""

# Stand-ins for the go command. Each one runs the real go command with the
# same arguments and output, and changes only the exit status of one kind of
# call, to a status that the real command does not give on its own account
# in a module that is otherwise sound.
STAND_IN_GO = """#!/bin/sh
"$GATE_SELFTEST_GO" "$@"
status=$?
if %s; then
    exit %d
fi
exit "$status"
"""
# A failing "go test" ends with status 3 instead of 1.
ODD_STATUS_GO = STAND_IN_GO % ('[ "$1" = test ] && [ "$status" -eq 1 ]', 3)
# "go list" prints the packages and fails.
FAILING_LIST_GO = STAND_IN_GO % ('[ "$1" = list ]', 1)
# "go test -list" fails, and every other "go test" is untouched.
FAILING_TEST_LIST_GO = STAND_IN_GO % ('[ "$1" = test ] && [ "$2" = -list ]', 1)
# Every "go test" that runs tests ends with status 0, whatever happened.
ZERO_STATUS_GO = STAND_IN_GO % ('[ "$1" = test ] && [ "$2" != -list ]', 0)
# "go test -json" writes one line that is not JSON before its events.
NOISY_GO = """#!/bin/sh
if [ "$1" = test ] && [ "$2" = -json ]; then
    echo "a line that is not JSON"
fi
exec "$GATE_SELFTEST_GO" "$@"
"""

# A test whose subtest "reg" starts a subtest of its own, "custody", after
# the point where "reg" can fail.
STARTS_ITS_SUBTEST_LATE = """
func TestLate(t *testing.T) {
	ran(t)
	t.Run("reg", func(t *testing.T) {
		ran(t)
		%s
		t.Run("custody", func(t *testing.T) {
			ran(t)
		})
	})
	t.Run("other", func(t *testing.T) {
		ran(t)
	})
}
"""

# Two tests that share state. The second fails only after the first has run
# in the same process. On its own it passes.
SHARED_STATE = """
var polluted bool

func TestHostBound(t *testing.T) {
	ran(t)
	polluted = true
	t.Fatal("deliberate failure that leaves state behind")
}

func TestStale(t *testing.T) {
	ran(t)
	if polluted {
		t.Fatal("fails only after TestHostBound in the same process")
	}
}
"""

# A test that stops when its subtest "reg" fails. Its second subtest, whose
# own name is "reg/custody", starts only when "reg" did not fail.
STOPS_AFTER_REG = """
func TestStop(t *testing.T) {
	ran(t)
	if !t.Run("reg", func(t *testing.T) {
		ran(t)
		%s
	}) {
		return
	}
	t.Run("reg/custody", func(t *testing.T) {
		ran(t)
		t.Fatal("deliberate failure in the subtest that the entry hides")
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

# A test with subtests. One subtest fails for a host reason, like the listed
# test of BASE. A list in Python stands for subtests, in order.
PREFLIGHT = [
    ("rejects wrong tool", PASS),
    ("rejects missing tool", FAIL),
    ("accepts exact tool", PASS),
]
PREFLIGHT_RAN = {
    "synth/a.TestPreflight",
    "synth/a.TestPreflight/rejects_wrong_tool",
    "synth/a.TestPreflight/accepts_exact_tool",
}
LISTED_SUBTEST = "synth/a TestPreflight/rejects_missing_tool\n"

# How the gate words its refusal of a line that is not an entry.
NOT_AN_ENTRY = "is not '<package> <TestName>[/<subtest>...]'"


def import_path(directory):
    return "synth" if directory == "" else "synth/" + directory


def mark(directory):
    return import_path(directory).replace("/", "__")


def function(name, what, depth=0):
    """Return the Go source of one generated test, or of one subtest."""
    indent = "\t" * depth
    if depth == 0:
        text = "\nfunc %s(t *testing.T) {\n" % name
    else:
        text = '%st.Run("%s", func(t *testing.T) {\n' % (indent, name)
    text += indent + "\tran(t)\n"
    if isinstance(what, list):
        for child, outcome in what:
            text += function(child, outcome, depth + 1)
    elif BODY[what]:
        text += indent + "\t" + BODY[what]
    return text + indent + ("}\n" if depth == 0 else "})\n")


def test_file(package, directory, tests):
    source = PREAMBLE % {"package": package, "mark": mark(directory)}
    for name, what in tests.items():
        source += function(name, what)
    return source


def raw_test_file(directory, body):
    """Return a test file of the package in that directory with a body written by hand."""
    package = "synth" if directory == "" else os.path.basename(directory)
    return PREAMBLE % {"package": package, "mark": mark(directory)} + body


def write_module(root, packages, files):
    """Write module "synth".

    packages maps a directory to {test name: outcome or subtests}. files maps
    a path inside the module to the text of one more file.
    """
    with open(os.path.join(root, "go.mod"), "w") as handle:
        handle.write("module synth\n\ngo 1.21\n")
    for directory, tests in packages.items():
        target = os.path.join(root, directory)
        os.makedirs(target, exist_ok=True)
        package = "synth" if directory == "" else os.path.basename(directory)
        with open(os.path.join(target, "code.go"), "w") as handle:
            handle.write("package %s\n" % package)
        if tests:
            with open(os.path.join(target, "code_test.go"), "w") as handle:
                handle.write(test_file(package, directory, tests))
    for path, text in (files or {}).items():
        target = os.path.join(root, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as handle:
            handle.write(text)


def run_gate(mode, packages, listing, files=None, arguments=None, runs=1, go=None):
    """Run the gate in a new module. Return (exit status, tests that ran, output).

    With runs above 1 the gate runs again in the same module, and the result
    is that of the last run alone. go is the text of a script that stands in
    for the go command; it finds the real one in GATE_SELFTEST_GO. An
    argument "{list}" stands for the path of the list file.
    """
    with tempfile.TemporaryDirectory() as root:
        module = os.path.join(root, "module")
        marks = os.path.join(root, "marks")
        os.makedirs(module)
        os.makedirs(marks)
        write_module(module, packages, files)
        list_path = os.path.join(root, "list.txt")
        with open(list_path, "wb") as handle:
            handle.write(listing if isinstance(listing, bytes) else listing.encode("utf-8"))
        environment = dict(os.environ)
        environment["GATE_SELFTEST_MARKS"] = marks
        if go is not None:
            tools = os.path.join(root, "bin")
            os.makedirs(tools)
            with open(os.path.join(tools, "go"), "w") as handle:
                handle.write(go)
            os.chmod(os.path.join(tools, "go"), 0o755)
            environment["GATE_SELFTEST_GO"] = shutil.which("go") or ""
            environment["PATH"] = tools + os.pathsep + environment.get("PATH", "")
        if arguments is None:
            arguments = [mode, list_path]
        arguments = [list_path if argument == "{list}" else argument for argument in arguments]
        for _ in range(runs):
            for name in os.listdir(marks):
                os.unlink(os.path.join(marks, name))
            done = subprocess.run(
                [sys.executable, "-I", "-B", GATE] + arguments,
                cwd=module,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        ran = {name.replace("__", "/") for name in os.listdir(marks)}
        return done.returncode, ran, done.stdout.decode("utf-8", "replace")


class GateCase(unittest.TestCase):
    mode = "gate"

    def check(self, packages, listing, status, ran, files=None, runs=1, go=None):
        got_status, got_ran, output = run_gate(
            self.mode, packages, listing, files=files, runs=runs, go=go
        )
        self.assertEqual(got_status, status, output)
        self.assertEqual(got_ran, ran, output)
        return output

    def refused(self, listing, reason, packages=BASE, files=None, before_any_go_command=False):
        """The list is refused in both modes, for the stated reason, with no test run."""
        for mode in ("gate", "still-failing"):
            with self.subTest(mode=mode):
                status, ran, output = run_gate(mode, packages, listing, files=files)
                self.assertEqual(status, 2, output)
                self.assertEqual(ran, set(), output)
                self.assertRegex(output, r"(?m)^::error::test gate list: .*" + re.escape(reason))
                if before_any_go_command:
                    # Refused on its text alone, not because of what go reports.
                    self.assertNotIn("+ go ", output)

    def stale(self, output, *lines):
        """Require exactly the given entries to be named as no longer failing."""
        named = re.findall(
            r"^::error::listed test no longer fails on this host \((.*)\): (\S+ \S+)\. Delete",
            output,
            re.M,
        )
        self.assertEqual(sorted(named), sorted(lines), output)

    def wide(self, output, *lines):
        """Require exactly the given entries to be named as covering other tests."""
        named = re.findall(
            r"^::error::listed subtest is not the only test under its path: (\S+ \S+) also "
            r"covers (.*?)\. The gate skips them with it\. An entry for a subtest must be "
            r"the only test whose path starts with its own\. In \S+, name such a "
            r"subtest, or list the whole test (\S+)\.$",
            output,
            re.M,
        )
        self.assertEqual(sorted(named), sorted(lines), output)


class GateScopesEachEntryToItsPackage(GateCase):
    def test_skips_only_the_listed_test_in_the_listed_package(self):
        output = self.check(BASE, "synth/a TestListed\n", 0, BASE_RAN)
        self.assertIn("test gate passed: 3 packages", output)

    def test_same_name_failing_in_an_unlisted_package_fails_the_gate(self):
        # The regression the first audit asked for: the first gate skipped the
        # name in every package, so this failing test never ran and it passed.
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

    def test_packages_with_the_same_last_path_element_keep_their_own_entries(self):
        # The real module has five packages named "app". An entry belongs to
        # an import path, not to a package name.
        listing = "synth/x/app TestA\nsynth/y/app TestB\n"
        failing = {
            "x/app": {"TestA": FAIL, "TestB": FAIL},
            "y/app": {"TestB": FAIL, "TestA": PASS},
        }
        self.check(failing, listing, 1, {"synth/x/app.TestB", "synth/y/app.TestA"})
        passing = {
            "x/app": {"TestA": FAIL, "TestB": PASS},
            "y/app": {"TestB": FAIL, "TestA": PASS},
        }
        self.check(passing, listing, 0, {"synth/x/app.TestB", "synth/y/app.TestA"})

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
        output = self.check(
            packages, "synth/a TestListed\n", 1, {"synth/a.TestPortable", "synth/b.TestOther"}
        )
        # The log shows the failing test as plain go test would.
        self.assertIn("--- FAIL: TestPortable", output)
        self.assertIn("deliberate failure", output)

    def test_names_that_only_resemble_an_entry_are_not_skipped(self):
        for name in ("TestListedV2", "TestXTestListed", "TestLISTED", "TestListe"):
            with self.subTest(name=name):
                packages = {"a": {"TestListed": FAIL, name: FAIL}}
                self.check(packages, "synth/a TestListed\n", 1, {"synth/a." + name})

    def test_subtest_named_like_an_entry_is_not_skipped(self):
        packages = {"a": {"TestListed": FAIL, "TestParent": [("TestListed", FAIL)]}}
        self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/a.TestParent", "synth/a.TestParent/TestListed"},
        )

    def test_compile_error_fails_the_gate(self):
        broken = "package %s\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { undefined() }\n"
        for directory in ("a", "b"):
            with self.subTest(package=directory):
                status, _, output = run_gate(
                    "gate",
                    BASE,
                    "synth/a TestListed\n",
                    files={directory + "/broken_test.go": broken % directory},
                )
                self.assertEqual(status, 1, output)

    def test_failed_go_list_fails_the_gate(self):
        for mode in ("gate", "still-failing"):
            with self.subTest(mode=mode):
                status, ran, output = run_gate(
                    mode, BASE, "synth/a TestListed\n", files={"go.mod": "not a go.mod file\n"}
                )
                self.assertEqual(status, 1, output)
                self.assertEqual(ran, set(), output)
            with self.subTest(mode=mode, go="prints the packages and fails"):
                # The packages it printed are not taken as the whole module.
                status, ran, output = run_gate(
                    mode, BASE, "synth/a TestListed\n", go=FAILING_LIST_GO
                )
                self.assertEqual(status, 1, output)
                self.assertEqual(ran, set(), output)
                self.assertIn("::error::test gate: go list ./... failed", output)

    def test_failed_go_test_list_fails_the_gate(self):
        # Without the names that a listed package defines, the list cannot be
        # checked against it, whatever the tests then do.
        for mode, ran in (("gate", BASE_RAN), ("still-failing", {"synth/a.TestListed"})):
            with self.subTest(mode=mode):
                status, got_ran, output = run_gate(
                    mode, BASE, "synth/a TestListed\n", go=FAILING_TEST_LIST_GO
                )
                self.assertEqual(status, 1, output)
                self.assertEqual(got_ran, ran, output)
                self.assertIn("go test -list for synth/a", output)

    def test_go_test_that_ends_with_a_status_other_than_1_fails_the_gate(self):
        # Any status but 0 is a failure, in a package with entries and in one
        # without. Every test here reports a verdict, so only the status of
        # the go command shows that the run failed.
        listing = "synth/a TestListed\n"
        with_entries = {"a": {"TestListed": FAIL, "TestPortable": FAIL}}
        without_entries = {"a": {"TestListed": FAIL}, "b": {"TestOther": FAIL}}
        for packages in (with_entries, without_entries):
            with self.subTest(packages=packages):
                status, ran, output = run_gate("gate", packages, listing, go=ODD_STATUS_GO)
                self.assertEqual(status, 1, output)
                self.assertNotIn("synth/a.TestListed", ran, output)
                self.assertIn("test gate failed: ", output)

    def test_unlisted_test_that_skips_itself_has_run(self):
        # A test that calls t.Skip reported a verdict. It is not one of the
        # "tests that are not listed did not run".
        packages = {"a": {"TestListed": FAIL, "TestSkips": SKIP, "TestPortable": PASS}}
        self.check(
            packages, "synth/a TestListed\n", 0, {"synth/a.TestSkips", "synth/a.TestPortable"}
        )

    def test_line_that_is_not_json_does_not_end_the_reading_of_a_run(self):
        output = self.check(BASE, "synth/a TestListed\n", 0, BASE_RAN, go=NOISY_GO)
        self.assertIn("a line that is not JSON\n", output)

    def test_module_without_packages_fails_the_gate(self):
        # "go list ./..." succeeds and names nothing. A gate that ran nothing
        # must not pass.
        for mode in ("gate", "still-failing"):
            with self.subTest(mode=mode):
                status, ran, output = run_gate(mode, {}, "")
                self.assertEqual(status, 1, output)
                self.assertEqual(ran, set(), output)
                self.assertIn("::error::test gate: go list ./... named no package", output)

    def test_list_without_entries_skips_nothing(self):
        for listing in ("", "# nothing is environment-only\n\n"):
            with self.subTest(listing=listing):
                self.check(BASE, listing, 1, BASE_RAN | {"synth/a.TestListed"})
        clean = {"a": {"TestPortable": PASS}, "b": {"TestOther": PASS}}
        self.check(clean, "", 0, {"synth/a.TestPortable", "synth/b.TestOther"})

    def test_every_run_executes_the_tests_again(self):
        # Without -count=1 the second run would print "(cached)" for both
        # packages and no test would execute.
        files = {
            "a/quiet_test.go": QUIET % {"package": "a", "mark": mark("a")},
            "b/quiet_test.go": QUIET % {"package": "b", "mark": mark("b")},
        }
        packages = {"a": {"TestListed": FAIL}, "b": {}}
        output = self.check(
            packages,
            "synth/a TestListed\n",
            0,
            {"synth/a.TestQuiet", "synth/b.TestQuiet"},
            files=files,
            runs=2,
        )
        self.assertNotIn("(cached)", output)


class GateSkipsExactlyTheListedSubtest(GateCase):
    def test_other_subtests_of_the_same_test_stay_in_the_gate(self):
        packages = {"a": {"TestPreflight": PREFLIGHT, "TestPortable": PASS}}
        output = self.check(
            packages, LISTED_SUBTEST, 0, PREFLIGHT_RAN | {"synth/a.TestPortable"}
        )
        self.assertIn(
            "synth/a: TestPreflight ran without the listed rejects_missing_tool; "
            "beside it ran: accepts_exact_tool pass, rejects_wrong_tool pass\n",
            output,
        )

    def test_failing_sibling_of_a_listed_subtest_fails_the_gate(self):
        subtests = [
            ("rejects wrong tool", PASS),
            ("rejects missing tool", FAIL),
            ("accepts exact tool", FAIL),
        ]
        output = self.check({"a": {"TestPreflight": subtests}}, LISTED_SUBTEST, 1, PREFLIGHT_RAN)
        self.assertIn("--- FAIL: TestPreflight/accepts_exact_tool", output)

    def test_whole_test_entry_would_hide_the_failing_sibling(self):
        # The reason for subtest entries: the same regression under an entry
        # for the whole test passes the gate.
        subtests = [("rejects missing tool", FAIL), ("accepts exact tool", FAIL)]
        self.check({"a": {"TestPreflight": subtests}}, "synth/a TestPreflight\n", 0, set())

    def test_same_subtest_name_under_another_test_is_not_skipped(self):
        packages = {
            "a": {"TestPreflight": PREFLIGHT, "TestProof": [("rejects missing tool", FAIL)]}
        }
        self.check(
            packages,
            LISTED_SUBTEST,
            1,
            PREFLIGHT_RAN | {"synth/a.TestProof", "synth/a.TestProof/rejects_missing_tool"},
        )

    def test_same_test_path_in_another_package_is_not_skipped(self):
        packages = {"a": {"TestPreflight": PREFLIGHT}, "b": {"TestPreflight": PREFLIGHT}}
        self.check(
            packages,
            LISTED_SUBTEST,
            1,
            PREFLIGHT_RAN
            | {name.replace("synth/a.", "synth/b.") for name in PREFLIGHT_RAN}
            | {"synth/b.TestPreflight/rejects_missing_tool"},
        )

    def test_subtest_names_that_only_resemble_an_entry_are_not_skipped(self):
        # go test names the second subtest called "rejects missing tool" in
        # one test "rejects_missing_tool#01".
        for name in (
            "rejects missing tool v2",
            "x rejects missing tool",
            "Rejects missing tool",
            "rejects missing too",
            "rejects missing tool",
        ):
            with self.subTest(name=name):
                subtests = [("rejects missing tool", FAIL), (name, FAIL)]
                printed = name.replace(" ", "_")
                if printed == "rejects_missing_tool":
                    printed += "#01"
                self.check(
                    {"a": {"TestPreflight": subtests}},
                    LISTED_SUBTEST,
                    1,
                    {"synth/a.TestPreflight", "synth/a.TestPreflight/" + printed},
                )

    def test_entry_for_a_subtest_of_a_subtest(self):
        subtests = [
            ("outer-one", [("inner", FAIL), ("other", PASS)]),
            ("outer-two", [("inner", PASS)]),
        ]
        listing = "synth/a TestDeep/outer-one/inner\n"
        ran = {
            "synth/a.TestDeep",
            "synth/a.TestDeep/outer-one",
            "synth/a.TestDeep/outer-one/other",
            "synth/a.TestDeep/outer-two",
            "synth/a.TestDeep/outer-two/inner",
        }
        output = self.check({"a": {"TestDeep": subtests}}, listing, 0, ran)
        self.assertIn(
            "synth/a: TestDeep/outer-one ran without the listed inner; "
            "beside it ran: other pass\n",
            output,
        )
        subtests[1] = ("outer-two", [("inner", FAIL)])
        self.check({"a": {"TestDeep": subtests}}, listing, 1, ran)

    def test_whole_test_and_subtest_entries_in_one_package(self):
        packages = {"a": {"TestListed": FAIL, "TestPreflight": PREFLIGHT, "TestPortable": PASS}}
        for listing in (
            "synth/a TestListed\n" + LISTED_SUBTEST,
            LISTED_SUBTEST + "synth/a TestListed\n",
        ):
            with self.subTest(listing=listing):
                self.check(packages, listing, 0, PREFLIGHT_RAN | {"synth/a.TestPortable"})

    def test_two_listed_subtests_of_one_test(self):
        subtests = PREFLIGHT + [("needs the host", FAIL)]
        listing = LISTED_SUBTEST + "synth/a TestPreflight/needs_the_host\n"
        self.check({"a": {"TestPreflight": subtests}}, listing, 0, PREFLIGHT_RAN)

    def test_entry_for_a_subtest_that_does_not_exist_skips_nothing(self):
        # The still-failing step is what rejects such an entry.
        ran = PREFLIGHT_RAN | {"synth/a.TestPreflight/rejects_missing_tool"}
        self.check({"a": {"TestPreflight": PREFLIGHT}}, "synth/a TestPreflight/no_such\n", 1, ran)

    def test_entry_under_a_path_that_is_not_a_test_skips_nothing(self):
        # A part of a listed path need not be a test, because the name of a
        # subtest may hold a "/". So this step cannot refuse the line. The
        # still-failing step does: the entry does not run.
        output = self.check(
            {"a": {"TestPreflight": [("other", PASS)]}},
            "synth/a TestPreflight/absent/inner\n",
            0,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/other"},
        )
        self.assertIn(
            "synth/a: TestPreflight ran without the listed absent/inner; "
            "beside it ran: other pass\n",
            output,
        )

    def test_tests_that_ran_beside_a_listed_subtest_are_the_nearest_ones(self):
        # The line names what ran at the level of the listed subtest, not
        # the subtests further down.
        subtests = [
            ("solo", FAIL),
            ("group", [("inner", PASS), ("other", PASS)]),
            ("last", SKIP),
        ]
        output = self.check(
            {"a": {"TestDeep": subtests}},
            "synth/a TestDeep/solo\n",
            0,
            {
                "synth/a.TestDeep",
                "synth/a.TestDeep/group",
                "synth/a.TestDeep/group/inner",
                "synth/a.TestDeep/group/other",
                "synth/a.TestDeep/last",
            },
        )
        self.assertIn(
            "synth/a: TestDeep ran without the listed solo; "
            "beside it ran: group pass, last skip\n",
            output,
        )
        only = {"a": {"TestDeep": [("solo", FAIL)]}}
        output = self.check(only, "synth/a TestDeep/solo\n", 0, {"synth/a.TestDeep"})
        self.assertIn(
            "synth/a: TestDeep ran without the listed solo; beside it ran: nothing\n", output
        )

    def test_subtest_whose_own_name_holds_a_slash_can_be_listed(self):
        # The four subtests are called "reg/identity" and so on by t.Run.
        # There is no test TestP/reg and none TestP/gov.
        subtests = [
            ("reg/identity", PASS),
            ("reg/custody", FAIL),
            ("gov/identity", PASS),
            ("gov/custody", PASS),
        ]
        ran = {
            "synth/a.TestP",
            "synth/a.TestP/reg/identity",
            "synth/a.TestP/gov/identity",
            "synth/a.TestP/gov/custody",
        }
        listing = "synth/a TestP/reg/custody\n"
        output = self.check({"a": {"TestP": subtests}}, listing, 0, ran)
        self.assertIn(
            "synth/a: TestP ran without the listed reg/custody; "
            "beside it ran: gov/custody pass, gov/identity pass, reg/identity pass\n",
            output,
        )
        subtests[3] = ("gov/custody", FAIL)
        output = self.check({"a": {"TestP": subtests}}, listing, 1, ran)
        self.assertIn("--- FAIL: TestP/gov/custody", output)
        # The same line where a subtest "reg" exists beside "reg/custody".
        beside = [("reg", PASS), ("reg/custody", FAIL), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": beside}},
            listing,
            0,
            {"synth/a.TestP", "synth/a.TestP/reg", "synth/a.TestP/other"},
        )
        self.assertIn(
            "synth/a: TestP/reg ran without the listed custody; beside it ran: nothing\n", output
        )

    def test_this_step_cannot_see_what_else_an_entry_for_a_subtest_skips(self):
        # go test reads the entry as the start of a path, so the subtests
        # named "reg/custody" and "reg/identity" are skipped with "reg", and
        # a skipped test leaves no trace. The still-failing step is what
        # refuses these lines (ListedSubtestStandsForItselfAlone).
        for custody in (PASS, FAIL):
            with self.subTest(custody=custody):
                subtests = [
                    ("reg", FAIL),
                    ("reg/custody", custody),
                    ("reg/identity", PASS),
                    ("other", PASS),
                ]
                output = self.check(
                    {"a": {"TestP": subtests}},
                    "synth/a TestP/reg\n",
                    0,
                    {"synth/a.TestP", "synth/a.TestP/other"},
                )
                self.assertIn(
                    "synth/a: TestP ran without the listed reg; beside it ran: other pass\n",
                    output,
                )


class GateChecksWhatReallyRan(GateCase):
    def test_listed_package_that_runs_none_of_its_tests_fails_the_gate(self):
        packages = {"a": {"TestListed": FAIL, "TestPortable": PASS}, "b": {"TestOther": PASS}}
        output = self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/b.TestOther"},
            files={"a/main_test.go": RUNS_NOTHING},
        )
        self.assertIn("synth/a: tests that are not listed did not run: TestPortable\n", output)

    def test_parent_of_a_listed_subtest_is_a_test_that_has_to_run(self):
        # A subtest entry exempts only that subtest. Its top-level test is
        # reported with the other tests that did not run, and only there.
        packages = {"a": {"TestPreflight": PREFLIGHT, "TestPortable": PASS}}
        output = self.check(
            packages, LISTED_SUBTEST, 1, set(), files={"a/main_test.go": RUNS_NOTHING}
        )
        self.assertIn(
            "synth/a: tests that are not listed did not run: TestPortable, TestPreflight\n",
            output,
        )
        self.assertNotIn("nothing shows", output)


class GateRefusesAListItCannotTakeLiterally(GateCase):
    def test_entries_that_are_not_one_plain_package_and_test_path(self):
        lines = (
            "synth/a Test.*",
            "synth/a TestList.*",
            "synth/a TestFoo|TestListed",
            "synth/a ^TestListed$",
            "synth/a (TestListed)",
            "synth/a TestListe[d]",
            "synth/a Listed",
            "synth/a testListed",
            "synth/a Test",
            "synth/a Test/sub",
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
            "synth/a TestListed\u00a0",
            "synth/a TestListed/",
            "synth/a TestListed//sub",
            "synth/a TestListed/sub/",
            "synth/a /sub",
            "synth/a TestListed/sub.*",
            "synth/a TestListed/^sub$",
            "synth/a TestListed/su|b",
            "synth/a TestListed/(sub)",
            "synth/a TestListed/s[u]b",
            "synth/a TestListed/sub name",
            "synth/a TestListed/sub#01",
            "synth/a TestListed/sub\\d",
            "synth/a TestListed/s\u00fcb",
        )
        for line in lines:
            with self.subTest(line=line):
                self.refused("# header\n" + line + "\n", NOT_AN_ENTRY, before_any_go_command=True)
        # No character with a meaning in a go test pattern, and no other
        # character outside the plain sets, is taken in any of the three
        # places of an entry.
        plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
        for character in map(chr, range(0x20, 0x7F)):
            for where, allowed, line in (
                ("package", plain + "./-", "syn%sth/a TestListed"),
                ("test", plain + "/", "synth/a TestList%sed"),
                ("subtest", plain + "/-", "synth/a TestListed/su%sb"),
            ):
                if character in allowed:
                    continue
                with self.subTest(where=where, character=character):
                    self.refused(
                        line % character + "\n", NOT_AN_ENTRY, before_any_go_command=True
                    )
        with self.subTest(line="invalid UTF-8"):
            self.refused(
                b"synth/a TestListed\n# \xff\n", "is not valid UTF-8", before_any_go_command=True
            )

    def test_package_patterns_and_unknown_packages(self):
        # The last three are the start of a package's import path, not a package.
        packages = ("synth/...", "synth/zzz", "synth/a/..", "other/a", "a", "synth", "synth/", "syn")
        for package in packages:
            with self.subTest(package=package):
                self.refused(
                    package + " TestListed\n",
                    "listed package is not a package of this module: " + package,
                )

    def test_entry_whose_test_is_not_defined_in_that_package(self):
        for line in (
            "synth/a TestMissing",
            "synth/b TestPortable",
            "synth/c TestListed",
            "synth/a TestMissing/sub",
        ):
            with self.subTest(line=line):
                package, path = line.split(" ")
                reason = "listed test is not defined in package %s: %s" % (
                    package,
                    path.split("/")[0],
                )
                self.refused(line + "\n", reason)
                # The entries of every listed package are checked, not only
                # those of the first.
                if package != "synth/b":
                    self.refused("synth/b TestOther\n" + line + "\n", reason)

    def test_name_defined_in_the_internal_and_the_external_test_package(self):
        # One directory can hold a test of the same name twice: in package a
        # and in package a_test. One entry would skip both, so the gate would
        # pass with the second one failing.
        both = {
            "a/code.go": "package a\n",
            "a/internal_test.go": test_file("a", "a", {"TestListed": FAIL}),
            "a/external_test.go": test_file("a_test", "a", {"TestListed": FAIL}),
        }
        for line in ("synth/a TestListed", "synth/a TestListed/sub"):
            with self.subTest(line=line):
                reason = "listed test TestListed is defined 2 times in package synth/a"
                self.refused(line + "\n", reason, packages={}, files=both)
                self.refused(
                    "synth/b TestOther\n" + line + "\n",
                    reason,
                    packages={"b": {"TestOther": FAIL}},
                    files=both,
                )
        # Unlisted, both definitions run and both fail.
        status, ran, output = run_gate("gate", {}, "", files=both)
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/a.TestListed"}, output)
        self.assertEqual(output.count("--- FAIL: TestListed"), 2, output)

    def test_repeated_entry(self):
        for line in ("synth/a TestListed", "synth/a TestListed/sub"):
            with self.subTest(line=line):
                self.refused(
                    line + "\n" + line + "\n",
                    "line 2 repeats an entry",
                    before_any_go_command=True,
                )

    def test_entry_inside_another_entry(self):
        # go test stops at the first part of a pattern that matches even
        # partly. With the subtest named first, the whole test would run
        # with all of its subtests skipped.
        for listing in (
            "synth/a TestListed\nsynth/a TestListed/sub\n",
            "synth/a TestListed/sub\nsynth/a TestListed\n",
            "synth/a TestListed/sub/deeper\nsynth/a TestPortable\nsynth/a TestListed/sub\n",
        ):
            with self.subTest(listing=listing):
                self.refused(
                    listing, "an entry must not overlap another entry", before_any_go_command=True
                )

    def test_entries_that_only_look_nested_are_accepted(self):
        packages = {
            "a": {"TestListed": [("sub", FAIL), ("subway", FAIL)], "TestListedToo": FAIL},
            "b": {"TestListed": FAIL},
        }
        listing = (
            "synth/a TestListed/sub\n"
            "synth/a TestListed/subway\n"
            "synth/a TestListedToo\n"
            "synth/b TestListed\n"
        )
        self.check(packages, listing, 0, {"synth/a.TestListed"})

    def test_bad_command_lines(self):
        for arguments in (
            [],
            ["gate"],
            ["check", "list.txt"],
            ["environment-only", "list.txt"],
            ["gate", "list.txt", "extra"],
            ["gate", "{list}", "extra"],
            ["still-failing", "{list}", "{list}"],
        ):
            with self.subTest(arguments=arguments):
                status, ran, output = run_gate("gate", BASE, "", arguments=arguments)
                self.assertEqual(status, 2, output)
                self.assertEqual(ran, set(), output)
                self.assertIn("::error::test gate list: usage: ", output)

    def test_missing_list_file(self):
        for mode in ("gate", "still-failing"):
            with self.subTest(mode=mode):
                status, ran, output = run_gate(
                    mode, BASE, "", arguments=[mode, "no-such-list.txt"]
                )
                self.assertEqual(status, 2, output)
                self.assertEqual(ran, set(), output)


class ListedTestsMustStillFail(GateCase):
    mode = "still-failing"

    def test_passes_when_every_listed_test_fails(self):
        packages = {
            "a": {"TestListed": FAIL, "TestPortable": PASS, "TestPreflight": PREFLIGHT},
            "b": {"TestListed": FAIL, "TestOther": FAIL},
        }
        listing = "synth/a TestListed\n" + LISTED_SUBTEST + "synth/b TestListed\n"
        output = self.check(
            packages,
            listing,
            0,
            {
                "synth/a.TestListed",
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/b.TestListed",
            },
        )
        self.stale(output)
        self.wide(output)
        self.assertIn("still fails: synth/a TestListed\n", output)
        self.assertIn("still fails: synth/a TestPreflight/rejects_missing_tool\n", output)
        self.assertIn("still fails: synth/b TestListed\n", output)
        self.assertIn(
            "all 3 listed tests still fail on this host, each in a run of its own\n", output
        )
        self.assertNotIn("::error::", output)
        # One go test for each entry, also for two entries of one package.
        self.assertEqual(
            re.findall(r"(?m)^\+ go test -json -count=1 -run (\S+) (\S+)$", output),
            [
                ("'^TestListed$'", "synth/a"),
                ("'^TestPreflight$/^rejects_missing_tool$'", "synth/a"),
                ("'^TestListed$'", "synth/b"),
            ],
            output,
        )

    def test_listed_test_is_judged_without_the_other_listed_tests(self):
        # TestStale fails only after TestHostBound in the same process. In
        # the gate, where TestHostBound is skipped, it would pass. So its
        # line is stale, and only a run without TestHostBound shows that.
        files = {"a/shared_test.go": raw_test_file("a", SHARED_STATE)}
        for listing in (
            "synth/a TestHostBound\nsynth/a TestStale\n",
            "synth/a TestStale\nsynth/a TestHostBound\n",
        ):
            with self.subTest(listing=listing):
                output = self.check(
                    {"a": {}},
                    listing,
                    1,
                    {"synth/a.TestHostBound", "synth/a.TestStale"},
                    files=files,
                )
                self.stale(output, ("it passes", "synth/a TestStale"))
                self.assertIn("still fails: synth/a TestHostBound\n", output)
        # Unlisted, TestStale passes the gate, as the stale line says.
        status, ran, output = run_gate(
            "gate", {"a": {}}, "synth/a TestHostBound\n", files=files
        )
        self.assertEqual(status, 0, output)
        self.assertEqual(ran, {"synth/a.TestStale"}, output)

    def test_whole_listed_test_reports_how_its_subtests_ended(self):
        # An entry for a whole test stands for all of its subtests. The log
        # shows how many of them the entry keeps out of the gate although
        # they pass.
        subtests = [
            ("hostbound", FAIL),
            ("portable one", PASS),
            ("deep/name", PASS),
            ("group", [("inner", SKIP)]),
        ]
        output = self.check(
            {"a": {"TestWhole": subtests, "TestListed": FAIL}},
            "synth/a TestWhole\nsynth/a TestListed\n",
            0,
            {
                "synth/a.TestWhole",
                "synth/a.TestWhole/hostbound",
                "synth/a.TestWhole/portable_one",
                "synth/a.TestWhole/deep/name",
                "synth/a.TestWhole/group",
                "synth/a.TestWhole/group/inner",
                "synth/a.TestListed",
            },
        )
        self.assertIn(
            "still fails: synth/a TestWhole (its subtests: 3 pass, 1 fail, 1 skip)\n", output
        )
        self.assertIn("still fails: synth/a TestListed\n", output)
        self.wide(output)
        # A subtest that stops the test binary reports no verdict.
        stops = {"a": {"TestWhole": [("first", PASS), ("stops", EXIT)]}}
        output = self.check(
            stops,
            "synth/a TestWhole\n",
            0,
            {"synth/a.TestWhole", "synth/a.TestWhole/first", "synth/a.TestWhole/stops"},
        )
        self.assertIn(
            "still fails: synth/a TestWhole (its subtests: 1 pass, 1 unfinished)\n", output
        )

    def test_list_without_entries(self):
        output = self.check(BASE, "", 0, set())
        self.assertIn("all 0 listed tests still fail on this host", output)

    def test_listed_test_that_passes_is_named(self):
        output = self.check(BASE, "synth/b TestListed\n", 1, {"synth/b.TestListed"})
        self.stale(output, ("it passes", "synth/b TestListed"))

    def test_listed_test_that_skips_itself_is_named(self):
        packages = {"a": {"TestListed": SKIP}}
        output = self.check(packages, "synth/a TestListed\n", 1, {"synth/a.TestListed"})
        self.stale(output, ("it skips itself", "synth/a TestListed"))

    def test_only_the_entries_that_no_longer_fail_are_named(self):
        packages = {
            "a": {"TestListed": FAIL, "TestNowPasses": PASS, "TestSkips": SKIP},
            "b": {"TestListed": PASS},
        }
        listing = (
            "synth/a TestListed\nsynth/a TestNowPasses\nsynth/a TestSkips\nsynth/b TestListed\n"
        )
        output = self.check(
            packages,
            listing,
            1,
            {
                "synth/a.TestListed",
                "synth/a.TestNowPasses",
                "synth/a.TestSkips",
                "synth/b.TestListed",
            },
        )
        self.stale(
            output,
            ("it passes", "synth/a TestNowPasses"),
            ("it skips itself", "synth/a TestSkips"),
            ("it passes", "synth/b TestListed"),
        )
        self.assertIn("still fails: synth/a TestListed\n", output)

    def test_listed_subtest_that_passes_is_named(self):
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            "synth/a TestPreflight/accepts_exact_tool\n",
            1,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/accepts_exact_tool"},
        )
        self.stale(output, ("it passes", "synth/a TestPreflight/accepts_exact_tool"))

    def test_listed_subtest_that_does_not_run_is_named(self):
        # A failing sibling makes the parent fail. The entry itself still has
        # to fail.
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            "synth/a TestPreflight/no_such\n" + LISTED_SUBTEST,
            1,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/rejects_missing_tool"},
        )
        self.stale(output, ("it did not run", "synth/a TestPreflight/no_such"))

    def test_listed_subtest_that_does_not_run_under_a_failing_parent_is_named(self):
        output = self.check(
            {"a": {"TestPreflight": [("first", FAIL)]}},
            "synth/a TestPreflight/first/no_such\n",
            1,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/first"},
        )
        self.stale(output, ("it did not run", "synth/a TestPreflight/first/no_such"))

    def test_listed_subtest_is_judged_by_its_own_verdict(self):
        # The parent fails because of the other listed subtest. That does not
        # make a passing listed subtest count as failing.
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            LISTED_SUBTEST + "synth/a TestPreflight/accepts_exact_tool\n",
            1,
            {
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/a.TestPreflight/accepts_exact_tool",
            },
        )
        self.stale(output, ("it passes", "synth/a TestPreflight/accepts_exact_tool"))
        self.assertIn("still fails: synth/a TestPreflight/rejects_missing_tool\n", output)

    def test_listed_test_that_stops_the_test_binary_does_not_hide_the_next(self):
        # A panic or an exit ends the test binary. Every entry has a run of
        # its own, so the entries after it are judged all the same.
        for how in (PANIC, EXIT):
            with self.subTest(how=how):
                packages = {"a": {"TestStops": how, "TestAfter": FAIL, "TestLast": PASS}}
                listing = "synth/a TestStops\nsynth/a TestAfter\nsynth/a TestLast\n"
                output = self.check(
                    packages,
                    listing,
                    1,
                    {"synth/a.TestStops", "synth/a.TestAfter", "synth/a.TestLast"},
                )
                self.stale(output, ("it passes", "synth/a TestLast"))
                self.assertIn("still fails: synth/a TestStops\n", output)
                self.assertIn("still fails: synth/a TestAfter\n", output)
                packages = {"a": {"TestStops": how, "TestAfter": FAIL}}
                output = self.check(
                    packages,
                    "synth/a TestStops\nsynth/a TestAfter\n",
                    0,
                    {"synth/a.TestStops", "synth/a.TestAfter"},
                )
                self.stale(output)

    def test_package_that_does_not_compile_fails_without_naming_entries(self):
        broken = "package a\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { undefined() }\n"
        status, ran, output = run_gate(
            "still-failing", BASE, "synth/a TestListed\n", files={"a/broken_test.go": broken}
        )
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, set(), output)
        self.stale(output)
        self.assertIn("::error::listed tests check failed: ", output)

    def test_package_whose_listed_tests_do_not_start_fails_without_naming_entries(self):
        # The test binary lists the tests and then runs nothing, so no entry
        # can be judged. The package is reported once, and the entries of
        # the next package are still judged.
        status, ran, output = run_gate(
            "still-failing",
            {"a": {"TestListed": FAIL, "TestOther": FAIL}, "b": {"TestListed": PASS}},
            "synth/a TestListed\nsynth/a TestOther\nsynth/b TestListed\n",
            files={"a/main_test.go": RUNS_NOTHING},
        )
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/b.TestListed"}, output)
        self.stale(output, ("it passes", "synth/b TestListed"))
        self.assertIn(
            "::error::listed tests check failed: no listed test of synth/a started\n", output
        )

    def test_listed_test_without_a_verdict_fails_only_if_go_test_failed(self):
        # A test that stops the test binary reports no verdict. It counts as
        # failing because the go command fails with it. If the go command
        # reported success, nothing would show a failure.
        packages = {"a": {"TestListed": EXIT}}
        listing = "synth/a TestListed\n"
        output = self.check(packages, listing, 0, {"synth/a.TestListed"})
        self.assertIn("still fails: synth/a TestListed\n", output)
        status, ran, output = run_gate("still-failing", packages, listing, go=ZERO_STATUS_GO)
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/a.TestListed"}, output)
        self.stale(output, ("it did not run", "synth/a TestListed"))

    def test_every_run_executes_the_listed_tests_again(self):
        # Without -count=1 the second run would replay the stored result of
        # the first, and the entry would be judged by a test that did not run.
        output = self.check(
            {"a": {}},
            "synth/a TestQuiet\n",
            1,
            {"synth/a.TestQuiet"},
            files={"a/quiet_test.go": QUIET % {"package": "a", "mark": mark("a")}},
            runs=2,
        )
        self.stale(output, ("it passes", "synth/a TestQuiet"))
        self.assertNotIn("(cached)", output)

    def test_runs_only_the_listed_tests(self):
        packages = {
            "a": {"TestListed": FAIL, "TestListedV2": FAIL, "TestPreflight": PREFLIGHT},
            "b": {"TestListed": FAIL},
        }
        self.check(packages, "synth/a TestListed\n", 0, {"synth/a.TestListed"})


class ListedSubtestStandsForItselfAlone(GateCase):
    """An entry for a subtest must not take any other test out of the gate.

    go test reads a test path as the start of a path. The skip for TestP/reg
    also covers every test whose path starts with "TestP/reg/". The gating
    step cannot see that (GateSkipsExactlyTheListedSubtest), so this step
    refuses the entry when its run starts any such test.
    """

    mode = "still-failing"

    def test_neighbours_named_like_subtests_of_the_listed_subtest(self):
        # "reg/custody" and "reg/identity" are subtests of TestP, not of
        # "reg". Whether the hidden one passes or holds a regression, the
        # entry is refused.
        for custody in (PASS, FAIL):
            with self.subTest(custody=custody):
                subtests = [
                    ("reg", FAIL),
                    ("reg/custody", custody),
                    ("reg/identity", PASS),
                    ("other", PASS),
                ]
                output = self.check(
                    {"a": {"TestP": subtests}},
                    "synth/a TestP/reg\n",
                    1,
                    {
                        "synth/a.TestP",
                        "synth/a.TestP/reg",
                        "synth/a.TestP/reg/custody",
                        "synth/a.TestP/reg/identity",
                    },
                )
                self.wide(
                    output,
                    ("synth/a TestP/reg", "TestP/reg/custody, TestP/reg/identity", "TestP"),
                )
                self.stale(output)
                self.assertIn("still fails: synth/a TestP/reg\n", output)
                self.assertNotIn("all 1 listed tests still fail", output)

    def test_neighbour_of_a_nested_listed_subtest(self):
        # The entry names the subtest "custody" of the subtest "reg". TestP
        # also has a subtest of its own that is called "reg/custody/deep".
        subtests = [
            ("reg", [("custody", FAIL)]),
            ("reg/custody/deep", FAIL),
            ("other", PASS),
        ]
        output = self.check(
            {"a": {"TestP": subtests}},
            "synth/a TestP/reg/custody\n",
            1,
            {
                "synth/a.TestP",
                "synth/a.TestP/reg",
                "synth/a.TestP/reg/custody",
                "synth/a.TestP/reg/custody/deep",
            },
        )
        self.wide(
            output, ("synth/a TestP/reg/custody", "TestP/reg/custody/deep", "TestP")
        )

    def test_subtest_added_under_an_existing_entry(self):
        # What the third audit planted on the real tree: one more subtest
        # whose name begins with the name of the listed subtest and "/".
        subtests = PREFLIGHT + [("rejects missing tool/planted second subtest", FAIL)]
        output = self.check(
            {"a": {"TestPreflight": subtests}},
            LISTED_SUBTEST,
            1,
            {
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/a.TestPreflight/rejects_missing_tool/planted_second_subtest",
            },
        )
        self.wide(
            output,
            (
                "synth/a TestPreflight/rejects_missing_tool",
                "TestPreflight/rejects_missing_tool/planted_second_subtest",
                "TestPreflight",
            ),
        )

    def test_listed_subtest_with_subtests_of_its_own(self):
        # From their names, subtests of the listed subtest cannot be told
        # from neighbours named like them. So the entry has to name the
        # subtest that fails and has no subtests.
        subtests = [("reg", [("custody", FAIL), ("identity", PASS)]), ("other", PASS)]
        packages = {"a": {"TestP": subtests}}
        output = self.check(
            packages,
            "synth/a TestP/reg\n",
            1,
            {
                "synth/a.TestP",
                "synth/a.TestP/reg",
                "synth/a.TestP/reg/custody",
                "synth/a.TestP/reg/identity",
            },
        )
        self.wide(
            output, ("synth/a TestP/reg", "TestP/reg/custody, TestP/reg/identity", "TestP")
        )
        output = self.check(
            packages,
            "synth/a TestP/reg/custody\n",
            0,
            {"synth/a.TestP", "synth/a.TestP/reg", "synth/a.TestP/reg/custody"},
        )
        self.wide(output)
        self.assertIn("still fails: synth/a TestP/reg/custody\n", output)

    def test_entry_that_names_no_test_and_covers_two(self):
        # No subtest is called "reg". Two are called "reg/custody" and
        # "reg/identity", and the gate would skip both.
        subtests = [("reg/custody", FAIL), ("reg/identity", PASS), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": subtests}},
            "synth/a TestP/reg\n",
            1,
            {"synth/a.TestP", "synth/a.TestP/reg/custody", "synth/a.TestP/reg/identity"},
        )
        self.stale(output, ("it did not run", "synth/a TestP/reg"))
        self.wide(
            output, ("synth/a TestP/reg", "TestP/reg/custody, TestP/reg/identity", "TestP")
        )

    def test_subtest_whose_own_name_holds_a_slash(self):
        # Accepted where the entry stands for that subtest alone, as in the
        # gating step. A subtest "reg" beside it starts in the run, because
        # the entry lies inside its path, and is not covered by the entry.
        listing = "synth/a TestP/reg/custody\n"
        subtests = [
            ("reg/identity", PASS),
            ("reg/custody", FAIL),
            ("gov/identity", PASS),
            ("gov/custody", PASS),
        ]
        output = self.check(
            {"a": {"TestP": subtests}},
            listing,
            0,
            {"synth/a.TestP", "synth/a.TestP/reg/custody"},
        )
        self.wide(output)
        self.assertIn("still fails: synth/a TestP/reg/custody\n", output)
        beside = [("reg", PASS), ("reg/custody", FAIL), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": beside}},
            listing,
            0,
            {"synth/a.TestP", "synth/a.TestP/reg", "synth/a.TestP/reg/custody"},
        )
        self.wide(output)
        # Refused where a neighbour's name goes on from the listed name.
        routes = [
            ("get/v1", FAIL),
            ("get/v1/jobs", FAIL),
            ("get/v1/jobs/id", PASS),
            ("get/v2", PASS),
        ]
        output = self.check(
            {"a": {"TestRoutes": routes}},
            "synth/a TestRoutes/get/v1\n",
            1,
            {
                "synth/a.TestRoutes",
                "synth/a.TestRoutes/get/v1",
                "synth/a.TestRoutes/get/v1/jobs",
                "synth/a.TestRoutes/get/v1/jobs/id",
            },
        )
        self.wide(
            output,
            (
                "synth/a TestRoutes/get/v1",
                "TestRoutes/get/v1/jobs, TestRoutes/get/v1/jobs/id",
                "TestRoutes",
            ),
        )

    def test_only_the_entries_that_cover_other_tests_are_named(self):
        subtests = [("reg", FAIL), ("reg/custody", PASS), ("gov", FAIL), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": subtests, "TestListed": FAIL}},
            "synth/a TestP/reg\nsynth/a TestP/gov\nsynth/a TestListed\n",
            1,
            {
                "synth/a.TestP",
                "synth/a.TestP/reg",
                "synth/a.TestP/reg/custody",
                "synth/a.TestP/gov",
                "synth/a.TestListed",
            },
        )
        self.wide(output, ("synth/a TestP/reg", "TestP/reg/custody", "TestP"))
        self.stale(output)

    def test_limit_a_neighbour_that_starts_only_when_the_listed_subtest_passes(self):
        # What no run can show, stated in go_test_gate.py and in the list.
        # TestStop returns when its subtest "reg" fails, and only otherwise
        # starts its subtest "reg/custody". The listed "reg" fails here, so
        # "reg/custody" never starts in the run of the entry, and the gate
        # skips it with "reg". Both steps pass. This case holds the limit
        # down in the open: it fails on the day a run can show that subtest.
        failing = {"a/stop_test.go": raw_test_file("a", STOPS_AFTER_REG % BODY[FAIL])}
        listing = "synth/a TestStop/reg\n"
        for mode, ran in (
            ("gate", {"synth/a.TestStop"}),
            ("still-failing", {"synth/a.TestStop", "synth/a.TestStop/reg"}),
        ):
            with self.subTest(mode=mode):
                status, got_ran, output = run_gate(mode, {"a": {}}, listing, files=failing)
                self.assertEqual(status, 0, output)
                self.assertEqual(got_ran, ran, output)
        # The hidden subtest is real: where "reg" passes it runs, and fails.
        passing = {"a/stop_test.go": raw_test_file("a", STOPS_AFTER_REG % BODY[PASS])}
        status, got_ran, output = run_gate("gate", {"a": {}}, "", files=passing)
        self.assertEqual(status, 1, output)
        self.assertEqual(
            got_ran,
            {"synth/a.TestStop", "synth/a.TestStop/reg", "synth/a.TestStop/reg/custody"},
            output,
        )

    def test_subtests_that_a_listed_subtest_does_not_reach_are_part_of_it(self):
        # The harmless kind of what no run can show. The listed "reg" fails
        # before it starts its own subtest "custody". That subtest is part of
        # "reg": nothing but "reg" is lost with it, as for a whole listed
        # test, and the rest of TestLate stays in the gate.
        failing = {"a/late_test.go": raw_test_file("a", STARTS_ITS_SUBTEST_LATE % BODY[FAIL])}
        listing = "synth/a TestLate/reg\n"
        for mode, ran in (
            ("gate", {"synth/a.TestLate", "synth/a.TestLate/other"}),
            ("still-failing", {"synth/a.TestLate", "synth/a.TestLate/reg"}),
        ):
            with self.subTest(mode=mode):
                status, got_ran, output = run_gate(mode, {"a": {}}, listing, files=failing)
                self.assertEqual(status, 0, output)
                self.assertEqual(got_ran, ran, output)
        # On the day "reg" no longer fails, the step names the entry twice:
        # it passes, and it is not the only test under its path.
        passing = {"a/late_test.go": raw_test_file("a", STARTS_ITS_SUBTEST_LATE % BODY[PASS])}
        status, got_ran, output = run_gate("still-failing", {"a": {}}, listing, files=passing)
        self.assertEqual(status, 1, output)
        self.assertEqual(
            got_ran,
            {"synth/a.TestLate", "synth/a.TestLate/reg", "synth/a.TestLate/reg/custody"},
            output,
        )
        self.stale(output, ("it passes", "synth/a TestLate/reg"))
        self.wide(output, ("synth/a TestLate/reg", "TestLate/reg/custody", "TestLate"))


class WorkflowKeepsWhatTheGateDependsOn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, "rb") as handle:
            cls.raw = handle.read()
        cls.lines = [line.strip() for line in cls.raw.decode("utf-8").split("\n")]

    def test_the_workflow_file_is_the_text_that_was_reviewed(self):
        # The other checks of this group read single lines. They cannot see
        # every edit that switches a step off or weakens it: a step-level
        # "env:" or "shell:", a key written in another YAML style, a changed
        # trigger or permission. So the file is held as a whole. Any edit of
        # it fails here until WORKFLOW_SHA256 is changed in the same change,
        # which puts the edit in front of whoever reviews that change.
        found = hashlib.sha256(self.raw).hexdigest()
        self.assertEqual(
            found,
            WORKFLOW_SHA256,
            "%s is not the text that was reviewed. If the edit is intended, review the "
            "whole file and set WORKFLOW_SHA256 in %s to %s"
            % (os.path.normpath(WORKFLOW), os.path.basename(__file__), found),
        )

    def test_every_action_is_pinned_to_a_full_commit_sha(self):
        uses = [line for line in self.lines if line.startswith(("uses:", "- uses:"))]
        self.assertTrue(uses)
        for line in uses:
            with self.subTest(line=line):
                self.assertRegex(line, r"^(- )?uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\S+$")

    def test_the_three_gate_commands_are_present_in_order(self):
        commands = [line[len("run: "):] for line in self.lines if line.startswith("run: ")]
        gate_commands = [command for command in commands if "go_test_gate" in command]
        self.assertEqual(
            gate_commands,
            [
                "python3 -I -B .github/ci/go_test_gate_selftest.py",
                'python3 -I -B .github/ci/go_test_gate.py gate "$ENVIRONMENT_ONLY_TESTS"',
                'python3 -I -B .github/ci/go_test_gate.py still-failing "$ENVIRONMENT_ONLY_TESTS"',
            ],
        )
        self.assertIn("ENVIRONMENT_ONLY_TESTS: .github/ci/environment-only-tests.txt", self.lines)
        for line in self.lines:
            # No line in the plain style allows a step to fail or makes one
            # conditional. Other spellings are caught by the hash above.
            self.assertFalse(line.startswith(("continue-on-error:", "if:", "- if:")), line)

    def test_the_go_build_cache_is_not_restored(self):
        self.assertIn("cache: false", self.lines)
        self.assertEqual([line for line in self.lines if line.startswith("cache:")], ["cache: false"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
