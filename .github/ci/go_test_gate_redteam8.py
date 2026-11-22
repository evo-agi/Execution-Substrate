#!/usr/bin/env python3
"""Red-team checks of go_test_gate.py that fail at b39fa35 (08-red-team.md).

Run from anywhere:

    python3 -I -B .github/ci/go_test_gate_redteam8.py

Each check states what a green run of the CI steps should not allow, builds a
throwaway module with the helpers of go_test_gate_selftest.py, and runs the
gate exactly as the workflow does. Every check here FAILS against the gate of
b39fa35. They are written to be moved into go_test_gate_selftest.py by the
change that repairs the finding, with the wording of the messages adjusted to
what that change prints. No workflow step runs this file.

The checks assert exit statuses and the names of tests. They do not fix the
text of a message, and they do not fix how a repair lets a change declare a
test that may skip itself on the runner.
"""

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "go_test_gate_selftest", os.path.join(HERE, "go_test_gate_selftest.py")
)
selftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(selftest)

FAIL = selftest.FAIL
PASS = selftest.PASS
SKIP = selftest.SKIP
run_gate = selftest.run_gate
raw_test_file = selftest.raw_test_file

# The test binary of package b that lists its tests and runs none of them.
RUNS_NOTHING_B = selftest.RUNS_NOTHING.replace("package a\n", "package b\n", 1)

# A test that fails when it runs alone and passes in the run of its package,
# because a test before it leaves behind what it needs.
PASSES_ONLY_AFTER_ANOTHER_TEST = """
var prepared bool

func TestAPrepares(t *testing.T) {
	ran(t)
	prepared = true
}

func TestListed(t *testing.T) {
	ran(t)
	if !prepared {
		t.Fatal("fails only when it runs without TestAPrepares")
	}
}
"""


class RT8_1_ATestThatSkipsItselfIsOutsideTheGateAndTheList(unittest.TestCase):
    """Finding RT8-1.

    A test that calls t.Skip on the runner is taken out of the gate by the
    test itself. The list does not name it, nothing forces the skip out when
    its reason ends, and a broken test that is made to skip itself passes
    both steps. The gate has to fail for a test that skips itself unless the
    change declares that skip, in whatever form the repair gives that.
    """

    def test_broken_test_that_skips_itself_in_a_package_with_entries(self):
        packages = {"a": {"TestListed": FAIL, "TestSkips": SKIP, "TestPortable": PASS}}
        status, ran, output = run_gate("gate", packages, "synth/a TestListed\n")
        self.assertEqual(status, 1, output)
        self.assertIn("TestSkips", output)

    def test_broken_test_that_skips_itself_in_a_package_without_entries(self):
        packages = {"a": {"TestListed": FAIL}, "b": {"TestSkips": SKIP, "TestOther": PASS}}
        status, ran, output = run_gate("gate", packages, "synth/a TestListed\n")
        self.assertEqual(status, 1, output)
        self.assertIn("TestSkips", output)

    def test_broken_subtest_that_skips_itself_beside_a_listed_subtest(self):
        packages = {
            "a": {"TestPreflight": [("rejects missing tool", FAIL), ("accepts exact tool", SKIP)]}
        }
        status, ran, output = run_gate(
            "gate", packages, "synth/a TestPreflight/rejects_missing_tool\n"
        )
        self.assertEqual(status, 1, output)
        self.assertIn("TestPreflight/accepts_exact_tool", output)


class RT8_2_APackageWithoutEntriesThatRunsNoneOfItsTests(unittest.TestCase):
    """Finding RT8-2.

    The gate fails when a package WITH entries runs none of its tests
    (go_test_gate_selftest.py, GateChecksWhatReallyRan). A package without
    entries is judged by the exit status of go test alone, which is 0 for a
    test binary that runs nothing.
    """

    def test_package_without_entries_that_runs_none_of_its_tests_fails_the_gate(self):
        packages = {"a": {"TestListed": FAIL, "TestPortable": PASS}, "b": {"TestOther": PASS}}
        status, ran, output = run_gate(
            "gate", packages, "synth/a TestListed\n", files={"b/main_test.go": RUNS_NOTHING_B}
        )
        self.assertNotIn("synth/b.TestOther", ran, output)
        self.assertEqual(status, 1, output)
        self.assertIn("TestOther", output)

    def test_the_same_with_a_list_that_has_no_entries(self):
        packages = {"b": {"TestOther": PASS}}
        status, ran, output = run_gate(
            "gate", packages, "# nothing is listed\n", files={"b/main_test.go": RUNS_NOTHING_B}
        )
        self.assertEqual(ran, set(), output)
        self.assertEqual(status, 1, output)
        self.assertIn("TestOther", output)


class RT8_3_AnEntryIsOnlyJudgedAlone(unittest.TestCase):
    """Finding RT8-3.

    The step "Listed tests still fail" runs an entry without any other test.
    A listed test that needs what an earlier test of its package leaves
    behind fails there for good, although it passes in the run of its
    package. Its line then never has to go, and the gate keeps skipping a
    test that passes.
    """

    def test_listed_test_that_passes_in_the_run_of_its_package_is_named(self):
        files = {"a/order_test.go": raw_test_file("a", PASSES_ONLY_AFTER_ANOTHER_TEST)}
        status, ran, output = run_gate("still-failing", {"a": {}}, "synth/a TestListed\n", files=files)
        self.assertEqual(status, 1, output)
        self.assertRegex(output, r"(?m)^::error::.*synth/a TestListed")


class RT8_4_FilesThatOnlyBuildOnMacOSAreNeverCompiled(unittest.TestCase):
    """Finding RT8-4.

    Two test files of es/admission build only on macOS (nine tests). The
    Linux runner never compiles them, so a change that breaks their build
    passes every step. "GOOS=darwin GOARCH=arm64 go vet ./..." type-checks
    them on the Linux runner in a few seconds. It does not run them.
    """

    def test_the_workflow_type_checks_the_files_that_only_build_on_macos(self):
        with open(selftest.WORKFLOW, "rb") as handle:
            lines = [line.strip() for line in handle.read().decode("utf-8").split("\n")]
        commands = [line[len("run: "):] for line in lines if line.startswith("run: ")]
        self.assertTrue(
            [
                command
                for command in commands
                if "GOOS=darwin" in command and "go vet" in command and "./..." in command
            ],
            "no step type-checks the module for macOS; the run lines are: %r" % commands,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
