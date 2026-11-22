#!/usr/bin/env python3
"""Checks of go_test_gate.py against small throwaway Go modules.

Run from anywhere:

    python3 -I -B .github/ci/go_test_gate_selftest.py

Needs the go command. Each check writes a module named "synth" into a
temporary directory, runs the gate there exactly as the workflow runs it, and
compares the exit status and the set of test functions that really executed.
Every generated test function records that it ran by creating a marker file,
so "skipped" and "ran" are observed, not read from go test output. A test
binary that go test started for chosen tests, with -run, keeps its marker
files apart from those of a run of a whole package. So the checks of the
step "Listed tests still fail" see what ran in the go test of one entry and
what ran in the run of its package.

The gate's observed run needs the Go version that go_test_gate.py names in
OBSERVED_GO_VERSION. With another go command the checks that have an entry
for a subtest fail, and the output says why.

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
WORKFLOW_SHA256 = "0383a2f066da5490db36abb91f4896c076a7d5cc45410cec11f40b85201db8bf"

PASS = "pass"
FAIL = "fail"
SKIP = "skip"
PANIC = "panic"
EXIT = "exit"

PREAMBLE = """package %(package)s

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ran(t *testing.T) {
	t.Helper()
	directory := os.Getenv("GATE_SELFTEST_MARKS")
	if flag.Lookup("test.run").Value.String() != "" {
		// A go test for chosen tests, not a run of the whole package.
		directory = filepath.Join(directory, "chosen")
	}
	name := "%(mark)s." + strings.ReplaceAll(t.Name(), "/", "__")
	if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
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
	"flag"
	"syscall"
	"testing"
)

func TestQuiet(t *testing.T) {
	directory, _ := syscall.Getenv("GATE_SELFTEST_MARKS")
	if flag.Lookup("test.run").Value.String() != "" {
		directory += "/chosen"
	}
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
# The same for package b.
RUNS_NOTHING_B = RUNS_NOTHING.replace("package a\n", "package b\n", 1)

# A test binary whose TestMain never calls m.Run. It lists no test and runs
# none, and go test reports that the package passed.
NEVER_CALLS_RUN = """package %s

import "testing"

func TestMain(m *testing.M) {}
"""

# A test binary that runs its tests in a run of the whole package, and none
# of them in a go test for chosen tests.
RUNS_NOTHING_FOR_CHOSEN_TESTS = """package %s

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if flag.Lookup("test.run").Value.String() != "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
"""

# A test binary that lists every test and runs only TestPortable.
RUNS_ONLY_ONE = """package %s

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if flag.Lookup("test.list").Value.String() == "" {
		flag.Set("test.run", "^TestPortable$")
	}
	os.Exit(m.Run())
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

# "go env" prints its answers and fails.
FAILING_ENV_GO = STAND_IN_GO % ('[ "$1" = env ]', 1)
# "go env GOVERSION GOROOT" names another Go version, and the real GOROOT.
OTHER_VERSION_GO = """#!/bin/sh
if [ "$1" = env ] && [ "$2" = GOVERSION ]; then
    echo %s
    exec "$GATE_SELFTEST_GO" env GOROOT
fi
exec "$GATE_SELFTEST_GO" "$@"
"""
# "go env GOVERSION GOROOT" names the real Go version, and as GOROOT the
# directory testdata/goroot of the module.
OTHER_GOROOT_GO = """#!/bin/sh
if [ "$1" = env ] && [ "$2" = GOVERSION ]; then
    "$GATE_SELFTEST_GO" env GOVERSION
    echo "$PWD/testdata/goroot"
    exit 0
fi
exec "$GATE_SELFTEST_GO" "$@"
"""
# Every go command runs without "-overlay" and the argument after it, so the
# test binary of the observed run is built with the stock testing package.
NO_OVERLAY_GO = """#!/bin/sh
drop=
for argument in "$@"; do
    shift
    if [ -n "$drop" ]; then
        drop=
    elif [ "$argument" = -overlay ]; then
        drop=1
    else
        set -- "$@" "$argument"
    fi
done
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

# A test whose second subtest, "reg/custody", starts only when "reg" got
# past the point where it can fail.
STARTS_AFTER_REG_GOT_THROUGH = """
func TestShared(t *testing.T) {
	ran(t)
	through := false
	t.Run("reg", func(t *testing.T) {
		ran(t)
		%s
		through = true
	})
	if through {
		t.Run("reg/custody", func(t *testing.T) {
			ran(t)
		})
	}
	t.Run("other", func(t *testing.T) {
		ran(t)
	})
}
"""

# A test with a failing subtest "reg" and a neighbour "reg/custody". Between
# them a subtest takes the variable of the observed run out of the
# environment, as a test does that clears its environment.
CLEARS_THE_VARIABLE = """
func TestClears(t *testing.T) {
	ran(t)
	t.Run("reg", func(t *testing.T) {
		ran(t)
		t.Fatal("deliberate failure")
	})
	t.Run("clears", func(t *testing.T) {
		ran(t)
		os.Unsetenv("GO_TEST_GATE_SKIPPED_NAMES")
	})
	t.Run("reg/custody", func(t *testing.T) {
		ran(t)
	})
}
"""

# A test whose subtest "meddles" does something to the record of the observed
# run, which no test has a reason to do. Other subtests stand before and
# after it.
MEDDLES_WITH_THE_RECORD = """
func TestMeddles(t *testing.T) {
	ran(t)
%(before)s	t.Run("meddles", func(t *testing.T) {
		ran(t)
		record := os.Getenv("GO_TEST_GATE_SKIPPED_NAMES")
		if record == "" {
			return
		}
		%(deed)s
	})
%(after)s}
"""
REMOVES_THE_RECORD = """if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}"""
ENDS_THE_RECORD_INSIDE_A_NAME = """file, err := os.OpenFile(record, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("TestMeddles/half"); err != nil {
			t.Fatal(err)
		}
		file.Close()"""

# A test that runs its own test binary once more, with a -test.run and a
# -test.skip of its own, as tests with helper processes do.
RUNS_ITS_OWN_BINARY = """package a

import (
	"os"
	"os/exec"
	"testing"
)

func TestSpawns(t *testing.T) {
	ran(t)
	if os.Getenv("GATE_SELFTEST_CHILD") != "" {
		return
	}
	command := exec.Command(os.Args[0], "-test.run=%s", "-test.skip=%s")
	command.Env = append(os.Environ(), "GATE_SELFTEST_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%%v: %%s", err, output)
	}
}
"""

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

# A test with a parallel subtest "reg". In a go test for chosen tests the
# test ends the process while "reg" still waits to go on, so "reg" starts
# there and never gets to its body. In a run of the whole package it passes.
STOPS_BEFORE_ITS_PARALLEL_SUBTEST = """
func TestP(t *testing.T) {
	ran(t)
	t.Run("reg", func(t *testing.T) {
		t.Parallel()
		ran(t)
	})
	if flag.Lookup("test.run").Value.String() != "" {
		os.Exit(1)
	}
}
"""

# Three tests in this order. TestHostBound fails and leaves state behind.
# TestStops ends the test binary. TestAfter fails only after TestHostBound
# in the same process.
STOPS_BETWEEN_TWO_THAT_SHARE_STATE = """
var polluted bool

func TestHostBound(t *testing.T) {
	ran(t)
	polluted = true
	t.Fatal("deliberate failure that leaves state behind")
}

func TestStops(t *testing.T) {
	ran(t)
	%s
}

func TestAfter(t *testing.T) {
	ran(t)
	if polluted {
		t.Fatal("fails only after TestHostBound in the same process")
	}
}
"""

# A parallel test that fails, and after it a test that ends the test binary
# while the first still waits to go on.
STOPS_BEFORE_A_PARALLEL_TEST = """
func TestParallel(t *testing.T) {
	t.Parallel()
	ran(t)
	t.Fatal("deliberate failure")
}

func TestStops(t *testing.T) {
	ran(t)
	os.Exit(3)
}
"""

# A test with a parallel subtest "stops" that ends the test binary when it
# goes on, and a subtest "fails" that has failed before that.
STOPS_AFTER_A_SUBTEST_FAILED = """
func TestP(t *testing.T) {
	ran(t)
	t.Run("stops", func(t *testing.T) {
		t.Parallel()
		ran(t)
		os.Exit(3)
	})
	t.Run("fails", func(t *testing.T) {
		ran(t)
		t.Fatal("deliberate failure")
	})
}
"""

# Two parallel tests that are both running before either of them ends. In a
# go test for chosen tests each fails at once.
RUN_SIDE_BY_SIDE = """
var aRuns = make(chan struct{})
var bRuns = make(chan struct{})

func TestSideA(t *testing.T) {
	t.Parallel()
	ran(t)
	if flag.Lookup("test.run").Value.String() != "" {
		t.Fatal("deliberate failure")
	}
	close(aRuns)
	<-bRuns
	%s
}

func TestSideB(t *testing.T) {
	t.Parallel()
	ran(t)
	if flag.Lookup("test.run").Value.String() != "" {
		t.Fatal("deliberate failure")
	}
	close(bRuns)
	<-aRuns
	%s
}
"""
# A test binary that lets two parallel tests run at a time on every host.
TWO_AT_A_TIME = """package a

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	flag.Set("test.parallel", "2")
	os.Exit(m.Run())
}
"""

# A parallel test that ends the test binary after it has gone on.
STOPS_AFTER_IT_WENT_ON = """
func TestListed(t *testing.T) {
	t.Parallel()
	ran(t)
	os.Exit(3)
}
"""

# Tests that skip themselves in three ways: with nothing written, with one
# line, and with several lines of which the first is long.
SKIPS_IN_THREE_WAYS = """
func TestSilent(t *testing.T) {
	ran(t)
	t.SkipNow()
}

func TestOneLine(t *testing.T) {
	ran(t)
	t.Skip("requires a service")
}

func TestLong(t *testing.T) {
	ran(t)
	t.Log(strings.Repeat("x", 300))
	t.Log("second line")
	t.Skip("third line")
}
"""

# A test that skips itself after its subtest has skipped itself.
SKIPS_AROUND_A_SKIP = """
func TestBoth(t *testing.T) {
	ran(t)
	t.Run("inner", func(t *testing.T) {
		ran(t)
		t.Skip("inner skip")
	})
	t.Skip("outer skip")
}
"""

# A test that passes once in a module and skips itself from then on.
SKIPS_FROM_THE_SECOND_RUN = """package a

import (
	"os"
	"testing"
)

func TestLater(t *testing.T) {
	ran(t)
	if _, err := os.Stat("later.marker"); err == nil {
		t.Skip("this is not the first run")
	}
	if err := os.WriteFile("later.marker", nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
"""

# A test that passes once in a module and fails from then on.
PASSES_ONCE = """package a

import (
	"os"
	"testing"
)

func TestOnce(t *testing.T) {
	ran(t)
	if _, err := os.Stat("once.marker"); err == nil {
		t.Fatal("this is not the first run")
	}
	if err := os.WriteFile("once.marker", nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
"""

# A test binary that runs every test in its first run in a module, and from
# then on only TestPreflight. Listing the tests does not count as a run.
RUNS_LESS_THE_SECOND_TIME = """package a

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if flag.Lookup("test.list").Value.String() == "" {
		if _, err := os.Stat("second.marker"); err == nil {
			flag.Set("test.run", "^TestPreflight$")
		} else if err := os.WriteFile("second.marker", nil, 0o600); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
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

# How the gate words its refusal of a line that is of neither kind.
NOT_AN_ENTRY = (
    "is not '<package> <TestName>[/<subtest>...]' and not "
    "'skips-itself <package> <TestName>[/<subtest>...]'"
)
# What the gate says of a line for a test that skips itself and an entry
# that are the same test, or of which one lies inside the other.
OVERLAPS_AN_ENTRY = (
    "overlap, and one of them is an entry; a line for a test that skips itself must "
    "not name an entry, lie inside one or hold one"
)


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


class Ran(set):
    """The tests that ran in one run of the gate, by their marker files.

    For the mode still-failing the set holds the tests that ran in a go test
    for one entry, and "whole" holds the tests that ran in a run of a whole
    package. For the mode gate the set holds every test that ran.
    """

    whole = frozenset()


def run_gate(mode, packages, listing, files=None, arguments=None, runs=1, go=None, gate=None):
    """Run the gate in a new module. Return (exit status, tests that ran, output).

    The tests that ran are a Ran. With runs above 1 the gate runs again in
    the same module, and the result
    is that of the last run alone. go is the text of a script that stands in
    for the go command; it finds the real one in GATE_SELFTEST_GO. An
    argument "{list}" stands for the path of the list file. gate is the text
    of a gate to run in the place of go_test_gate.py.
    """
    with tempfile.TemporaryDirectory() as root:
        module = os.path.join(root, "module")
        marks = os.path.join(root, "marks")
        chosen = os.path.join(marks, "chosen")
        os.makedirs(module)
        os.makedirs(chosen)
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
        program = GATE
        if gate is not None:
            program = os.path.join(root, "go_test_gate.py")
            with open(program, "w") as handle:
                handle.write(gate)
        if arguments is None:
            arguments = [mode, list_path]
        arguments = [list_path if argument == "{list}" else argument for argument in arguments]
        for _ in range(runs):
            for directory in (chosen, marks):
                for name in os.listdir(directory):
                    if os.path.join(directory, name) != chosen:
                        os.unlink(os.path.join(directory, name))
            done = subprocess.run(
                [sys.executable, "-I", "-B", program] + arguments,
                cwd=module,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        whole = {
            name.replace("__", "/")
            for name in os.listdir(marks)
            if os.path.join(marks, name) != chosen
        }
        ran = Ran(name.replace("__", "/") for name in os.listdir(chosen))
        if mode == "still-failing":
            ran.whole = whole
        else:
            ran |= whole
        return done.returncode, ran, done.stdout.decode("utf-8", "replace")


class GateCase(unittest.TestCase):
    mode = "gate"

    def check(self, packages, listing, status, ran, files=None, runs=1, go=None, whole=None):
        """Run the gate and require its exit status and the tests that ran.

        whole, when given, holds the tests that have to have run in the runs
        of whole packages of the mode still-failing.
        """
        got_status, got_ran, output = run_gate(
            self.mode, packages, listing, files=files, runs=runs, go=go
        )
        self.assertEqual(got_status, status, output)
        self.assertEqual(got_ran, ran, output)
        if whole is not None:
            self.assertEqual(got_ran.whole, whole, output)
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

    def together(self, output, *lines):
        """Require exactly the given entries to be named as not failing in the run
        of their package."""
        named = re.findall(
            r"^::error::listed test does not fail in the run of its package \((.*)\): "
            r"(\S+ \S+)\. The gate skips a test that would not fail there\. Delete its "
            r"line from \S+, or correct the line\.$",
            output,
            re.M,
        )
        self.assertEqual(sorted(named), sorted(lines), output)
        self.assertEqual(
            len(named),
            output.count("::error::listed test does not fail in the run of its package"),
            output,
        )

    def package_runs(self, output, *commands):
        """Require exactly the given runs of whole packages, in that order. A
        command is what follows "go test -json -count=1 "."""
        found = re.findall(r"(?m)^\+ go test -json -count=1 ((?!-run ).*)$", output)
        self.assertEqual(found, list(commands), output)
        self.assertEqual(output.count("::group::Run of "), len(commands), output)

    def skips_unlisted(self, output, *lines):
        """Require exactly the given tests to be named as skipping themselves
        without a line. A line is (package and test, what the test wrote
        without the place in its file)."""
        named = re.findall(
            r"^::error::test skips itself and is not listed: (\S+ \S+) \((?:\S+\.go:\d+: )?"
            r"(.*)\)\. A test that cannot run on this host needs the line '(.*)' in \S+, "
            r"with its reason in a comment\. A test that can run here must not skip "
            r"itself\.$",
            output,
            re.M,
        )
        for test, _, line in named:
            self.assertEqual(line, "skips-itself " + test, output)
        self.assertEqual(
            sorted((test, wrote) for test, wrote, _ in named), sorted(lines), output
        )
        self.assertEqual(
            len(named), output.count("::error::test skips itself and is not listed"), output
        )

    def skips_ended(self, output, *lines):
        """Require exactly the given lines to be named as tests that no longer
        skip themselves. A line is (how the test ended, package and test)."""
        named = re.findall(
            r"^::error::listed test no longer skips itself on this host \((.*)\): "
            r"(\S+ \S+)\. Delete its line from \S+, or correct the line\.$",
            output,
            re.M,
        )
        self.assertEqual(sorted(named), sorted(lines), output)
        self.assertEqual(
            len(named), output.count("::error::listed test no longer skips itself"), output
        )

    def skips_shown(self, output, *lines):
        """Require the log to show exactly the given tests as having skipped
        themselves in the first run of their package, in that order. A line is
        (package, test, what the test wrote without the place in its file)."""
        shown = re.findall(
            r"(?m)^skips itself: (\S+) (\S+): (?:\S+\.go:\d+: )?(.*)$", output
        )
        self.assertEqual(shown, list(lines), output)
        counts = {}
        for package, _, _ in lines:
            counts[package] = counts.get(package, 0) + 1
        self.assertEqual(
            re.findall(r"(?m)^::group::(\S+): (\d+) tests skipped themselves$", output),
            [(package, str(count)) for package, count in counts.items()],
            output,
        )

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

    def unlisted(self, output, *lines):
        """Require exactly the given tests to be named as skipped although not listed.

        A line is (package and test, the entry that covers it, its top-level
        test), or (package and test, None, None) where no entry covers it.
        """
        named = re.findall(
            r"^::error::the gate skipped a test that is not listed: (\S+ \S+)\. (?:The "
            r"entry (\S+) covers it as well, because go test reads a test path as the "
            r"start of a path\. An entry for a subtest must be the only test whose path "
            r"starts with its own\. In \S+, name a narrower subtest, or list the whole "
            r"test (\S+)\.|No entry covers it\. A test of this package ran a test binary "
            r"with a -test\.skip of its own\.)$",
            output,
            re.M,
        )
        named = [(test, entry or None, top or None) for test, entry, top in named]
        self.assertEqual(sorted(named, key=repr), sorted(lines, key=repr), output)
        self.assertEqual(
            len(named), output.count("::error::the gate skipped a test that is not listed"), output
        )

    def unskipped(self, output, *lines):
        """Require exactly the given entries to be named as not skipped by the gate."""
        named = re.findall(
            r"^::error::the gate did not skip the listed (\S+ \S+): the observed run did "
            r"not reach a test of that name, so the line skipped nothing\. Correct the "
            r"line in \S+, or delete it\.$",
            output,
            re.M,
        )
        self.assertEqual(sorted(named), sorted(lines), output)
        self.assertEqual(
            len(named), output.count("::error::the gate did not skip the listed"), output
        )

    def observed(self, output, *packages):
        """Require an observed run of exactly the given packages, in that order.

        What the gate wrote for those runs must be gone when it has ended.
        """
        runs = re.findall(
            r"(?m)^\+ GO_TEST_GATE_SKIPPED_NAMES=(\S+) go test -json -count=1 "
            r"-overlay (\S+) -skip \S+ (\S+)$",
            output,
        )
        self.assertEqual([package for _, _, package in runs], list(packages), output)
        self.assertEqual(output.count("-overlay"), len(packages), output)
        self.assertEqual(
            output.count("+ go env GOVERSION GOROOT\n"), min(1, len(packages)), output
        )
        for record, overlay, _ in runs:
            self.assertEqual(os.path.dirname(record), os.path.dirname(overlay), output)
            self.assertFalse(os.path.exists(os.path.dirname(record)), output)


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
        # The same for a package without entries: without its names nothing
        # shows that every test of it ran.
        clean = {"a": {"TestPortable": PASS}, "b": {"TestOther": PASS}}
        output = self.check(
            clean, "", 1, {"synth/a.TestPortable", "synth/b.TestOther"}, go=FAILING_TEST_LIST_GO
        )
        self.assertIn(
            "::error::test gate failed: go test -list for synth/a; go test -list for synth/b\n",
            output,
        )

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

    def test_test_that_skips_itself_has_run(self):
        # A test that calls t.Skip reported a verdict. It is not one of the
        # "tests that are not listed did not run". Whether it may skip
        # itself is the subject of GateHoldsEverySkipToTheList.
        packages = {"a": {"TestListed": FAIL, "TestSkips": SKIP, "TestPortable": PASS}}
        for status, listing in (
            (1, "synth/a TestListed\n"),
            (0, "synth/a TestListed\nskips-itself synth/a TestSkips\n"),
        ):
            with self.subTest(listing=listing):
                output = self.check(
                    packages, listing, status, {"synth/a.TestSkips", "synth/a.TestPortable"}
                )
                self.assertNotIn("did not run", output)

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
        self.assertEqual(output.count("ran without the listed"), 1, output)
        self.observed(output, "synth/a")
        self.assertIn(
            "synth/a: the observed run passed; go test skipped exactly the listed tests "
            "of this package (1), each once\n",
            output,
        )
        self.assertNotIn("::error::", output)

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
        # The subtest that the line was meant for runs, and fails the gate.
        ran = PREFLIGHT_RAN | {"synth/a.TestPreflight/rejects_missing_tool"}
        self.check({"a": {"TestPreflight": PREFLIGHT}}, "synth/a TestPreflight/no_such\n", 1, ran)

    def test_entry_that_skips_nothing_is_named(self):
        # A part of a listed path need not be a test, because the name of a
        # subtest may hold a "/". So the line cannot be refused before the
        # tests run, and every test passes. The observed run shows that the
        # line skipped nothing.
        for line in ("TestPreflight/absent/inner", "TestPreflight/no_such"):
            with self.subTest(line=line):
                output = self.check(
                    {"a": {"TestPreflight": [("other", PASS)]}},
                    "synth/a %s\n" % line,
                    1,
                    {"synth/a.TestPreflight", "synth/a.TestPreflight/other"},
                )
                self.assertIn(
                    "synth/a: TestPreflight ran without the listed %s; "
                    "beside it ran: other pass\n" % line.split("/", 1)[1],
                    output,
                )
                self.unskipped(output, "synth/a " + line)
                self.unlisted(output)
                self.assertIn(
                    "::error::test gate failed: synth/a: the tests that go test skipped "
                    "are not exactly the listed ones\n",
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
            "synth/a TestDeep/solo\nskips-itself synth/a TestDeep/last\n",
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


class GateShowsEveryTestItSkipped(GateCase):
    """The gate must skip the entries of a package and no other test.

    go test reads a test path as the start of a path. The skip for TestP/reg
    also covers every test whose path starts with "TestP/reg/", and a
    skipped test leaves no trace in the output of go test. The observed run
    of the gate writes down every test that go test skips, and the gate
    fails unless those are exactly the entries.
    """

    def test_neighbours_named_like_subtests_of_the_listed_subtest(self):
        # "reg/custody" and "reg/identity" are subtests of TestP, not of
        # "reg". go test skips them with "reg". Whether the hidden one
        # passes or holds a regression, the gate fails and names both.
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
                    {"synth/a.TestP", "synth/a.TestP/other"},
                )
                self.assertIn(
                    "synth/a: TestP ran without the listed reg; beside it ran: other pass\n",
                    output,
                )
                self.unlisted(
                    output,
                    ("synth/a TestP/reg/custody", "TestP/reg", "TestP"),
                    ("synth/a TestP/reg/identity", "TestP/reg", "TestP"),
                )
                self.unskipped(output)
                self.assertIn(
                    "::error::test gate failed: synth/a: the tests that go test skipped "
                    "are not exactly the listed ones\n",
                    output,
                )
                self.assertNotIn("test gate passed", output)

    def test_neighbour_that_starts_only_when_the_listed_subtest_did_not_fail(self):
        # TestStop returns when its subtest "reg" fails, and only otherwise
        # starts its subtest "reg/custody". The listed "reg" fails here, so
        # no run of "reg" can show "reg/custody": the still-failing step
        # passes. In the gate "reg" is skipped, TestStop goes on, and go
        # test skips "reg/custody" with it. The observed run names it.
        failing = {"a/stop_test.go": raw_test_file("a", STOPS_AFTER_REG % BODY[FAIL])}
        listing = "synth/a TestStop/reg\n"
        status, ran, output = run_gate("still-failing", {"a": {}}, listing, files=failing)
        self.assertEqual(status, 0, output)
        self.assertEqual(ran, {"synth/a.TestStop", "synth/a.TestStop/reg"}, output)
        output = self.check({"a": {}}, listing, 1, {"synth/a.TestStop"}, files=failing)
        self.unlisted(output, ("synth/a TestStop/reg/custody", "TestStop/reg", "TestStop"))
        self.unskipped(output)
        # The hidden subtest is real: where "reg" passes it runs, and fails.
        passing = {"a/stop_test.go": raw_test_file("a", STOPS_AFTER_REG % BODY[PASS])}
        self.check(
            {"a": {}},
            "",
            1,
            {"synth/a.TestStop", "synth/a.TestStop/reg", "synth/a.TestStop/reg/custody"},
            files=passing,
        )

    def test_subtest_added_under_an_existing_entry(self):
        # What the third audit planted on the real tree: one more subtest
        # whose name begins with the name of the listed subtest and "/".
        subtests = PREFLIGHT + [("rejects missing tool/planted second subtest", FAIL)]
        output = self.check({"a": {"TestPreflight": subtests}}, LISTED_SUBTEST, 1, PREFLIGHT_RAN)
        self.unlisted(
            output,
            (
                "synth/a TestPreflight/rejects_missing_tool/planted_second_subtest",
                "TestPreflight/rejects_missing_tool",
                "TestPreflight",
            ),
        )
        self.unskipped(output)

    def test_entry_that_names_no_test_and_covers_two(self):
        # No subtest is called "reg". Two are called "reg/custody" and
        # "reg/identity", and go test skips both for the line.
        subtests = [("reg/custody", FAIL), ("reg/identity", PASS), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": subtests}},
            "synth/a TestP/reg\n",
            1,
            {"synth/a.TestP", "synth/a.TestP/other"},
        )
        self.unlisted(
            output,
            ("synth/a TestP/reg/custody", "TestP/reg", "TestP"),
            ("synth/a TestP/reg/identity", "TestP/reg", "TestP"),
        )
        self.unskipped(output, "synth/a TestP/reg")

    def test_neighbour_of_a_subtest_whose_own_name_holds_a_slash(self):
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
            {"synth/a.TestRoutes", "synth/a.TestRoutes/get/v2"},
        )
        self.unlisted(
            output,
            ("synth/a TestRoutes/get/v1/jobs", "TestRoutes/get/v1", "TestRoutes"),
            ("synth/a TestRoutes/get/v1/jobs/id", "TestRoutes/get/v1", "TestRoutes"),
        )

    def test_only_the_entries_that_cover_other_tests_are_named(self):
        subtests = [("reg", FAIL), ("reg/custody", PASS), ("gov", FAIL), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": subtests, "TestListed": FAIL}, "b": {"TestListed": FAIL}},
            "synth/a TestP/reg\nsynth/a TestP/gov\nsynth/a TestListed\nsynth/b TestListed\n",
            1,
            {"synth/a.TestP", "synth/a.TestP/other"},
        )
        self.unlisted(output, ("synth/a TestP/reg/custody", "TestP/reg", "TestP"))
        self.unskipped(output)

    def test_what_a_test_does_not_start_is_not_skipped(self):
        # TestShared starts "reg/custody" only when "reg" got past the point
        # where it fails on this host. With "reg" skipped, and with "reg"
        # failing, TestShared does not start it. No test is skipped that the
        # list does not name, so both steps pass, as they would if go test
        # could skip "reg" alone. Where "reg" passes, "reg/custody" runs.
        shared = STARTS_AFTER_REG_GOT_THROUGH
        failing = {"a/shared_test.go": raw_test_file("a", shared % BODY[FAIL])}
        listing = "synth/a TestShared/reg\n"
        output = self.check(
            {"a": {}}, listing, 0, {"synth/a.TestShared", "synth/a.TestShared/other"}, files=failing
        )
        self.observed(output, "synth/a")
        status, ran, output = run_gate("still-failing", {"a": {}}, listing, files=failing)
        self.assertEqual(status, 0, output)
        self.assertEqual(ran, {"synth/a.TestShared", "synth/a.TestShared/reg"}, output)
        passing = {"a/shared_test.go": raw_test_file("a", shared % BODY[PASS])}
        self.check(
            {"a": {}},
            "",
            0,
            {
                "synth/a.TestShared",
                "synth/a.TestShared/reg",
                "synth/a.TestShared/reg/custody",
                "synth/a.TestShared/other",
            },
            files=passing,
        )

    def test_subtests_of_a_listed_subtest_are_part_of_it(self):
        # "reg" does not run in the gate, so its own subtests do not start
        # and are not skipped. The still-failing step is what makes such an
        # entry name the subtest that fails (ListedSubtestStandsForItselfAlone).
        subtests = [("reg", [("custody", FAIL), ("identity", PASS)]), ("other", PASS)]
        output = self.check(
            {"a": {"TestP": subtests}},
            "synth/a TestP/reg\n",
            0,
            {"synth/a.TestP", "synth/a.TestP/other"},
        )
        self.observed(output, "synth/a")

    def test_only_a_package_with_an_entry_for_a_subtest_has_an_observed_run(self):
        packages = {
            "a": {"TestPreflight": PREFLIGHT, "TestListed": FAIL},
            "b": {"TestListed": FAIL, "TestOther": PASS},
            "c": {"TestPreflight": PREFLIGHT[:2]},
            "d": {"TestOther": PASS},
        }
        ran = PREFLIGHT_RAN | {
            "synth/b.TestOther",
            "synth/c.TestPreflight",
            "synth/c.TestPreflight/rejects_wrong_tool",
            "synth/d.TestOther",
        }
        listing = (
            LISTED_SUBTEST
            + "synth/a TestListed\n"
            + "synth/b TestListed\n"
            + "synth/c TestPreflight/rejects_missing_tool\n"
        )
        output = self.check(packages, listing, 0, ran)
        self.observed(output, "synth/a", "synth/c")
        self.assertIn(
            "synth/a: the observed run passed; go test skipped exactly the listed tests "
            "of this package (2), each once\n",
            output,
        )
        # A list without an entry for a subtest needs no observed run, and
        # the gate does not ask which toolchain it runs on.
        output = self.check(BASE, "synth/a TestListed\n", 0, BASE_RAN)
        self.observed(output)

    def test_observed_run_has_to_pass(self):
        # TestOnce passes in the first run of the package and fails in the
        # observed run. A run that fails is not taken as a record of what
        # was skipped.
        files = {"a/once_test.go": PASSES_ONCE}
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            LISTED_SUBTEST,
            1,
            PREFLIGHT_RAN | {"synth/a.TestOnce"},
            files=files,
        )
        self.observed(output, "synth/a")
        self.assertIn("--- FAIL: TestOnce", output)
        self.assertIn("::error::test gate failed: the observed run of synth/a\n", output)
        self.unskipped(output)
        self.unlisted(output)

    def test_observed_run_has_to_run_every_test_that_is_not_listed(self):
        # TestPortable runs in the first run of the package. In the observed
        # run the test binary leaves it out. The entry is skipped there as
        # listed, and still the run does not show that nothing else was
        # skipped: a test that did not run reached none of its subtests.
        packages = {"a": {"TestPreflight": PREFLIGHT, "TestPortable": PASS}}
        output = self.check(
            packages,
            LISTED_SUBTEST,
            1,
            PREFLIGHT_RAN | {"synth/a.TestPortable"},
            files={"a/main_test.go": RUNS_LESS_THE_SECOND_TIME},
        )
        self.observed(output, "synth/a")
        self.assertIn(
            "::error::test gate failed: observed run: synth/a: tests that are not listed "
            "did not run: TestPortable\n",
            output,
        )
        self.unskipped(output)
        self.unlisted(output)

    def test_every_run_of_the_gate_observes_again(self):
        # Without -count=1 go test could replay the stored result of the
        # observed run of the first gate run. A replayed run skips nothing
        # and writes nothing down.
        files = {"a/quiet_test.go": QUIET % {"package": "a", "mark": mark("a")}}
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            LISTED_SUBTEST,
            0,
            PREFLIGHT_RAN | {"synth/a.TestQuiet"},
            files=files,
            runs=2,
        )
        self.observed(output, "synth/a")
        self.assertNotIn("(cached)", output)

    def test_test_binary_built_without_the_recording_fails_the_gate(self):
        # If go test did not build the test binary with the changed file,
        # nothing would be written down. The gate then fails for every
        # entry, so a recording that does not work cannot pass for a run
        # that skipped nothing else.
        packages = {"a": {"TestPreflight": PREFLIGHT, "TestListed": FAIL}}
        listing = LISTED_SUBTEST + "synth/a TestListed\n"
        status, ran, output = run_gate("gate", packages, listing, go=NO_OVERLAY_GO)
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, PREFLIGHT_RAN, output)
        self.unskipped(
            output, "synth/a TestPreflight/rejects_missing_tool", "synth/a TestListed"
        )
        self.unlisted(output)

    def test_another_toolchain_is_refused_before_any_test_runs(self):
        packages = {"a": {"TestPreflight": PREFLIGHT}}
        # A go command that names another Go version and has the real Go
        # root, so the file is the one whose hash the gate holds. That file
        # is often the same in two Go versions, and then only the comparison
        # of the version stops the gate. It has to be exact: another patch
        # release of the same Go line is another version, and so is a
        # version whose name only starts like the held one, or the reverse.
        with open(GATE) as handle:
            held = re.findall(
                r'(?m)^OBSERVED_GO_VERSION = "(go\d+\.\d+)\.(\d+)"$', handle.read()
            )
        self.assertEqual(len(held), 1, held)
        line, patch = held[0][0], int(held[0][1])
        for version in (
            "go1.0.0",
            "%s.%d" % (line, patch + 1),
            "%s.%d" % (line, patch + 10),
            "%s.%d0" % (line, patch),
            line,
            "%s.%drc1" % (line, patch),
        ):
            with self.subTest(version=version):
                status, ran, output = run_gate(
                    "gate", packages, LISTED_SUBTEST, go=OTHER_VERSION_GO % version
                )
                self.assertEqual(status, 1, output)
                self.assertEqual(ran, set(), output)
                self.assertIn(
                    "::error::test gate: the observed run is written against %s.%d, and "
                    "the go command is %s. Review " % (line, patch, version),
                    output,
                )
        # The same Go version with another src/testing/match.go.
        real = subprocess.run(
            ["go", "env", "GOROOT"], stdout=subprocess.PIPE, check=True
        ).stdout.decode("utf-8").strip()
        with open(os.path.join(real, "src", "testing", "match.go")) as handle:
            changed = handle.read() + "\n// One more line.\n"
        status, ran, output = run_gate(
            "gate",
            packages,
            LISTED_SUBTEST,
            files={"testdata/goroot/src/testing/match.go": changed},
            go=OTHER_GOROOT_GO,
        )
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, set(), output)
        self.assertRegex(
            output,
            r"(?m)^::error::test gate: \S+/testdata/goroot/src/testing/match\.go is not the "
            r"file of go\S+ that the observed run is written against: its SHA-256 is ",
        )
        # A go command that fails when asked is not taken at its word.
        status, ran, output = run_gate("gate", packages, LISTED_SUBTEST, go=FAILING_ENV_GO)
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, set(), output)
        self.assertIn("::error::test gate: go env GOVERSION GOROOT failed\n", output)
        # A list without an entry for a subtest does not depend on that file.
        for go in (OTHER_VERSION_GO % "go1.0.0", OTHER_GOROOT_GO, FAILING_ENV_GO):
            with self.subTest(go=go):
                status, ran, output = run_gate("gate", BASE, "synth/a TestListed\n", go=go)
                self.assertEqual(status, 0, output)
                self.assertEqual(ran, BASE_RAN, output)

    def test_held_file_has_to_drop_skipped_tests_in_exactly_one_place(self):
        # The gate adds its call by replacing one exact piece of text. The
        # SHA-256 that it holds is that of a file with exactly one such
        # place, so this cannot happen with the gate as it is. It is for the
        # day that value is set for the file of another Go version. A file
        # without that place would be built with no call in it, and a file
        # with two of them with a call that the review did not see. The gate
        # stops before any test runs.
        with open(GATE) as handle:
            gate = handle.read()
        held = re.findall(r'(?m)^MATCH_GO_SHA256 = "([0-9a-f]{64})"$', gate)
        self.assertEqual(len(held), 1, held)
        real = subprocess.run(
            ["go", "env", "GOROOT"], stdout=subprocess.PIPE, check=True
        ).stdout.decode("utf-8").strip()
        with open(os.path.join(real, "src", "testing", "match.go")) as handle:
            stock = handle.read()
        place = "\tif skip && !partialSkip {\n\t\treturn name, false, false\n\t}\n"
        self.assertEqual(stock.count(place), 1)
        again = (
            "\nfunc again(skip, partialSkip bool, name string) (string, bool, bool) {\n"
            + place
            + "\treturn name, true, false\n}\n"
        )
        packages = {"a": {"TestPreflight": PREFLIGHT}}
        for places, changed in (
            (0, stock.replace(place, place.replace("skip &&", "skip && true &&"))),
            (1, stock + "\n// One more line.\n"),
            (2, stock + again),
        ):
            with self.subTest(places=places):
                self.assertEqual(changed.count(place), places)
                digest = hashlib.sha256(changed.encode("utf-8")).hexdigest()
                status, ran, output = run_gate(
                    "gate",
                    packages,
                    LISTED_SUBTEST,
                    files={"testdata/goroot/src/testing/match.go": changed},
                    go=OTHER_GOROOT_GO,
                    gate=gate.replace(held[0], digest),
                )
                if places == 1:
                    # The gate takes the file whose hash it holds. The go
                    # command still builds with its own file, so the overlay
                    # replaces nothing and no entry is written down.
                    self.assertEqual(status, 1, output)
                    self.assertEqual(ran, PREFLIGHT_RAN, output)
                    self.unskipped(output, "synth/a TestPreflight/rejects_missing_tool")
                    continue
                self.assertEqual(status, 1, output)
                self.assertEqual(ran, set(), output)
                self.assertRegex(
                    output,
                    r"(?m)^::error::test gate: \S+/testdata/goroot/src/testing/match\.go does "
                    r"not drop skipped tests in exactly one place$",
                )

    def test_test_that_changes_its_environment_does_not_stop_the_recording(self):
        # The test binary reads the name of the record once, when it starts.
        files = {"a/clears_test.go": raw_test_file("a", CLEARS_THE_VARIABLE)}
        output = self.check(
            {"a": {}},
            "synth/a TestClears/reg\n",
            1,
            {"synth/a.TestClears", "synth/a.TestClears/clears"},
            files=files,
        )
        self.unlisted(output, ("synth/a TestClears/reg/custody", "TestClears/reg", "TestClears"))
        self.unskipped(output)

    def test_test_binary_started_by_a_test_writes_into_the_same_record(self):
        # A test that runs its own test binary hands it the environment. If
        # it also hands it a -test.skip, what that binary skips is written
        # down too. The gate does not guess which names came from where.
        packages = {"a": {"TestP": [("reg", FAIL), ("other", PASS)]}}
        ran = {"synth/a.TestP", "synth/a.TestP/other", "synth/a.TestSpawns"}
        listing = "synth/a TestP/reg\n"
        files = {"a/spawn_test.go": RUNS_ITS_OWN_BINARY % ("^TestSpawns$", "^TestSpawns$")}
        output = self.check(packages, listing, 1, ran, files=files)
        self.unlisted(output, ("synth/a TestSpawns", None, None))
        self.unskipped(output)
        files = {"a/spawn_test.go": RUNS_ITS_OWN_BINARY % ("^TestP$", "^TestP$/^reg$")}
        output = self.check(packages, listing, 1, ran, files=files)
        self.unlisted(output)
        self.unskipped(output)
        self.assertIn(
            "::error::the observed run of synth/a wrote down a skipped test more than "
            "once: TestP/reg\n",
            output,
        )
        # Without a -test.skip of its own that binary writes nothing down.
        files = {"a/spawn_test.go": RUNS_ITS_OWN_BINARY % ("^TestP$/^other$", "")}
        output = self.check(packages, listing, 0, ran, files=files)
        self.observed(output, "synth/a")

    def test_record_that_a_test_meddled_with_is_not_taken(self):
        reg = function("reg", FAIL, 1)
        deeds = (
            # The record is removed after "reg/custody" was written down and
            # before "reg" is. The next name cannot be written, which ends
            # the test binary. A record that started again at that point
            # would hold "reg" alone.
            (
                function("reg/custody", FAIL, 1),
                REMOVES_THE_RECORD,
                reg,
                "the observed run of synth/a",
            ),
            # The record ends with text that has no line end after it.
            (
                reg,
                ENDS_THE_RECORD_INSIDE_A_NAME,
                "",
                "the record of the observed run of synth/a ends inside a name",
            ),
        )
        for before, deed, after, problem in deeds:
            with self.subTest(problem=problem):
                body = MEDDLES_WITH_THE_RECORD % {"before": before, "deed": deed, "after": after}
                output = self.check(
                    {"a": {}},
                    "synth/a TestMeddles/reg\n",
                    1,
                    {"synth/a.TestMeddles", "synth/a.TestMeddles/meddles"},
                    files={"a/meddles_test.go": raw_test_file("a", body)},
                )
                self.assertIn("::error::test gate failed: " + problem + "\n", output)


class GateHoldsEverySkipToTheList(GateCase):
    """A test that skips itself needs a line of its own in the list.

    A test that calls t.Skip takes itself out of the gate. The tests and
    subtests that skip themselves in the gate therefore have to be exactly
    the ones that the list names with "skips-itself". A skip without a line
    fails the gate, and so does a line whose test no longer skips itself.
    """

    def test_test_that_skips_itself_without_a_line_fails_the_gate(self):
        # A broken test with one t.Skip line passed the gate before. Now it
        # fails, in a package with entries, in one without, and in the root
        # package.
        cases = (
            ({"a": {"TestListed": FAIL, "TestSkips": SKIP, "TestPortable": PASS}}, "synth/a"),
            ({"a": {"TestListed": FAIL}, "b": {"TestSkips": SKIP, "TestOther": PASS}}, "synth/b"),
            ({"": {"TestSkips": SKIP}, "a": {"TestListed": FAIL}}, "synth"),
        )
        for packages, where in cases:
            with self.subTest(package=where):
                status, ran, output = run_gate("gate", packages, "synth/a TestListed\n")
                self.assertEqual(status, 1, output)
                self.assertIn(where + ".TestSkips", ran, output)
                self.skips_unlisted(output, (where + " TestSkips", "deliberate skip"))
                self.skips_ended(output)
                self.skips_shown(output, (where, "TestSkips", "deliberate skip"))
                self.assertIn(
                    "::error::test gate failed: %s: the tests that skipped themselves are "
                    "not exactly the listed ones\n" % where,
                    output,
                )
                self.assertNotIn("test gate passed", output)
                # With its line the same module passes, and the log still
                # names the test and what it wrote.
                listing = "synth/a TestListed\nskips-itself %s TestSkips\n" % where
                status, ran, output = run_gate("gate", packages, listing)
                self.assertEqual(status, 0, output)
                self.assertIn(where + ".TestSkips", ran, output)
                self.skips_shown(output, (where, "TestSkips", "deliberate skip"))
                self.assertNotIn("::error::", output)
                self.assertIn(
                    "test gate passed: %d packages, 1 of them with skipped entries "
                    "(1 entries); 1 tests skipped themselves, all of them listed\n"
                    % len(packages),
                    output,
                )

    def test_line_does_not_reach_another_package(self):
        packages = {"a": {"TestSkips": SKIP}, "b": {"TestSkips": SKIP}}
        output = self.check(
            packages, "skips-itself synth/a TestSkips\n", 1, {"synth/a.TestSkips", "synth/b.TestSkips"}
        )
        self.skips_unlisted(output, ("synth/b TestSkips", "deliberate skip"))
        self.skips_ended(output)
        output = self.check(
            packages,
            "skips-itself synth/a TestSkips\nskips-itself synth/b TestSkips\n",
            0,
            {"synth/a.TestSkips", "synth/b.TestSkips"},
        )
        self.skips_shown(
            output, ("synth/a", "TestSkips", "deliberate skip"), ("synth/b", "TestSkips", "deliberate skip")
        )
        self.assertIn("; 2 tests skipped themselves, all of them listed\n", output)

    def test_names_that_only_resemble_a_line_are_not_covered(self):
        for name in ("TestSkipsV2", "TestXTestSkips", "TestSKIPS", "TestSkip"):
            with self.subTest(name=name):
                packages = {"a": {"TestSkips": SKIP, name: SKIP}}
                output = self.check(
                    packages,
                    "skips-itself synth/a TestSkips\n",
                    1,
                    {"synth/a.TestSkips", "synth/a." + name},
                )
                self.skips_unlisted(output, ("synth/a " + name, "deliberate skip"))

    def test_subtest_that_skips_itself_needs_a_line_of_its_own(self):
        # Beside a listed subtest: the broken subtest of the red team.
        packages = {
            "a": {"TestPreflight": [("rejects missing tool", FAIL), ("accepts exact tool", SKIP)]}
        }
        ran = {"synth/a.TestPreflight", "synth/a.TestPreflight/accepts_exact_tool"}
        output = self.check(packages, LISTED_SUBTEST, 1, ran)
        self.skips_unlisted(output, ("synth/a TestPreflight/accepts_exact_tool", "deliberate skip"))
        # The first run of the package failed its check, so no observed run.
        self.assertNotIn("-overlay", output)
        listing = LISTED_SUBTEST + "skips-itself synth/a TestPreflight/accepts_exact_tool\n"
        output = self.check(packages, listing, 0, ran)
        self.observed(output, "synth/a")
        self.skips_shown(output, ("synth/a", "TestPreflight/accepts_exact_tool", "deliberate skip"))
        # A line for the test above it does not stand for the subtest.
        packages = {"a": {"TestParent": [("needs a service", SKIP), ("other", PASS)]}}
        ran = {
            "synth/a.TestParent",
            "synth/a.TestParent/needs_a_service",
            "synth/a.TestParent/other",
        }
        output = self.check(packages, "skips-itself synth/a TestParent\n", 1, ran)
        self.skips_unlisted(output, ("synth/a TestParent/needs_a_service", "deliberate skip"))
        self.skips_ended(output, ("it passes", "synth/a TestParent"))
        self.check(packages, "skips-itself synth/a TestParent/needs_a_service\n", 0, ran)

    def test_test_that_skips_itself_after_its_subtest_did(self):
        # Both report a skip, so both need a line. Two such lines may lie
        # inside each other, unlike two entries.
        files = {"a/both_test.go": raw_test_file("a", SKIPS_AROUND_A_SKIP)}
        ran = {"synth/a.TestBoth", "synth/a.TestBoth/inner"}
        outer = "skips-itself synth/a TestBoth\n"
        inner = "skips-itself synth/a TestBoth/inner\n"
        for listing in (outer + inner, inner + outer):
            with self.subTest(listing=listing):
                output = self.check({"a": {}}, listing, 0, ran, files=files)
                self.skips_shown(
                    output,
                    ("synth/a", "TestBoth", "outer skip"),
                    ("synth/a", "TestBoth/inner", "inner skip"),
                )
        output = self.check({"a": {}}, outer, 1, ran, files=files)
        self.skips_unlisted(output, ("synth/a TestBoth/inner", "inner skip"))
        output = self.check({"a": {}}, inner, 1, ran, files=files)
        self.skips_unlisted(output, ("synth/a TestBoth", "outer skip"))

    def test_line_whose_test_no_longer_skips_itself_fails_the_gate(self):
        # The reason for the skip has ended, or the line names nothing. In a
        # package with entries and in one without.
        packages = {
            "a": {"TestListed": FAIL, "TestSkips": PASS, "TestPortable": PASS},
            "b": {"TestSkips": PASS},
        }
        ran = {"synth/a.TestSkips", "synth/a.TestPortable", "synth/b.TestSkips"}
        for line, how in (
            ("synth/a TestSkips", "it passes"),
            ("synth/b TestSkips", "it passes"),
            ("synth/a TestSkips/no_such", "it did not run"),
            ("synth/b TestSkips/no_such", "it did not run"),
        ):
            with self.subTest(line=line):
                listing = "synth/a TestListed\nskips-itself %s\n" % line
                output = self.check(packages, listing, 1, ran)
                self.skips_ended(output, (how, line))
                self.skips_unlisted(output)
                self.assertIn(
                    "::error::test gate failed: %s: the tests that skipped themselves are "
                    "not exactly the listed ones\n" % line.split(" ")[0],
                    output,
                )
        # A listed test that fails is a failing test like any other.
        packages["b"]["TestSkips"] = FAIL
        output = self.check(packages, "synth/a TestListed\nskips-itself synth/b TestSkips\n", 1, ran)
        self.assertIn("--- FAIL: TestSkips", output)

    def test_skip_inside_an_entry_needs_no_line(self):
        # What lies inside an entry does not run in the gate.
        packages = {"a": {"TestListed": [("skips", SKIP), ("fails", FAIL)], "TestPortable": PASS}}
        output = self.check(packages, "synth/a TestListed\n", 0, {"synth/a.TestPortable"})
        self.skips_shown(output)
        self.assertIn("; 0 tests skipped themselves, all of them listed\n", output)

    def test_log_says_what_a_test_wrote_when_it_skipped_itself(self):
        files = {"a/three_test.go": raw_test_file("a", SKIPS_IN_THREE_WAYS)}
        listing = "".join(
            "skips-itself synth/a %s\n" % name for name in ("TestSilent", "TestOneLine", "TestLong")
        )
        ran = {"synth/a.TestSilent", "synth/a.TestOneLine", "synth/a.TestLong"}
        output = self.check({"a": {}}, listing, 0, ran, files=files)
        shown = dict(re.findall(r"(?m)^skips itself: synth/a (\S+): (.*)$", output))
        self.assertEqual(sorted(shown), ["TestLong", "TestOneLine", "TestSilent"], output)
        self.assertEqual(shown["TestSilent"], "it wrote nothing", output)
        self.assertRegex(shown["TestOneLine"], r"^three_test\.go:\d+: requires a service$")
        # The first line, cut to 240 characters, and how many lines follow.
        self.assertRegex(shown["TestLong"], r"^three_test\.go:\d+: x+ \[and 2 more lines\]$")
        self.assertEqual(len(shown["TestLong"]), 240 + len(" [and 2 more lines]"), output)
        # The same words stand in the error for a skip without a line.
        output = self.check({"a": {}}, "", 1, ran, files=files)
        self.skips_unlisted(
            output,
            ("synth/a TestSilent", "it wrote nothing"),
            ("synth/a TestOneLine", "requires a service"),
            ("synth/a TestLong", shown["TestLong"].split(": ", 1)[1]),
        )

    def test_observed_run_holds_the_skips_too(self):
        # TestLater passes in the first run of the package and skips itself
        # in the observed run. A run in which a test skipped itself without
        # a line is not taken as a record of what the gate skipped.
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            LISTED_SUBTEST,
            1,
            PREFLIGHT_RAN | {"synth/a.TestLater"},
            files={"a/later_test.go": SKIPS_FROM_THE_SECOND_RUN},
        )
        self.observed(output, "synth/a")
        self.skips_unlisted(output, ("synth/a TestLater", "this is not the first run"))
        self.assertIn(
            "::error::test gate failed: observed run: synth/a: the tests that skipped "
            "themselves are not exactly the listed ones\n",
            output,
        )
        # With a line, the first run of the package is the one that fails.
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            LISTED_SUBTEST + "skips-itself synth/a TestLater\n",
            1,
            PREFLIGHT_RAN | {"synth/a.TestLater"},
            files={"a/later_test.go": SKIPS_FROM_THE_SECOND_RUN},
        )
        self.assertNotIn("-overlay", output)
        self.skips_ended(output, ("it passes", "synth/a TestLater"))

    def test_step_for_the_listed_failures_runs_nothing_for_these_lines(self):
        # The step "Listed tests still fail" checks the lines against the
        # module like the gate and judges the entries alone.
        packages = {"a": {"TestListed": FAIL, "TestSkips": SKIP}, "b": {"TestSkips": SKIP}}
        listing = "synth/a TestListed\nskips-itself synth/a TestSkips\nskips-itself synth/b TestSkips\n"
        status, ran, output = run_gate("still-failing", packages, listing)
        self.assertEqual(status, 0, output)
        self.assertEqual(ran, {"synth/a.TestListed"}, output)
        self.assertEqual(ran.whole, {"synth/a.TestListed", "synth/a.TestSkips"}, output)
        self.assertIn("all 1 listed tests still fail on this host", output)


class GateChecksWhatReallyRan(GateCase):
    def test_package_without_entries_that_runs_none_of_its_tests_fails_the_gate(self):
        # go test reports that such a package passed. The gate asks which of
        # the tests that go test lists reported a verdict, in every package.
        packages = {"a": {"TestListed": FAIL, "TestPortable": PASS}, "b": {"TestOther": PASS}}
        output = self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/a.TestPortable"},
            files={"b/main_test.go": RUNS_NOTHING_B},
        )
        self.assertIn("synth/b: tests that are not listed did not run: TestOther", output)
        self.assertNotIn("synth/a: ", output.split("::error::test gate failed: ")[1])
        # The same with a list that has no entries.
        output = self.check(
            {"b": {"TestOther": PASS}},
            "# nothing is listed\n",
            1,
            set(),
            files={"b/main_test.go": RUNS_NOTHING_B},
        )
        self.assertIn("synth/b: tests that are not listed did not run: TestOther", output)

    def test_package_that_runs_only_some_of_its_tests_fails_the_gate(self):
        packages = {"a": {"TestListed": FAIL}, "b": {"TestPortable": PASS, "TestOther": PASS}}
        output = self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/b.TestPortable"},
            files={"b/main_test.go": RUNS_ONLY_ONE % "b"},
        )
        self.assertIn(
            "::error::test gate failed: synth/b: tests that are not listed did not run: "
            "TestOther\n",
            output,
        )

    def test_test_binary_that_never_runs_the_tests_fails_the_gate(self):
        # With a TestMain that does not call m.Run, go test lists no test
        # for the package, runs none and reports that the package passed.
        # No name shows what is missing. The testing package writes its
        # PASS line only when it has run the tests, and that line is not
        # there.
        packages = {"a": {"TestListed": FAIL, "TestPortable": PASS}, "b": {"TestOther": PASS}}
        output = self.check(
            packages,
            "synth/a TestListed\n",
            1,
            {"synth/a.TestPortable"},
            files={"b/main_test.go": NEVER_CALLS_RUN % "b"},
        )
        self.assertIn(
            "::error::test gate failed: synth/b: the test binary ended without the PASS "
            "line that the testing package writes when it has run the tests. ",
            output,
        )
        # In a package with entries the list is refused: go test lists none
        # of the tests that its lines name.
        self.refused(
            "synth/a TestListed\n",
            "listed test is not defined in package synth/a: TestListed",
            files={"a/main_test.go": NEVER_CALLS_RUN % "a"},
        )

    def test_package_whose_test_files_hold_no_test_passes(self):
        # Such a package has nothing to run, and the testing package still
        # writes its PASS line. A package without test files passes too.
        files = {"b/helper_test.go": "package b\n"}
        packages = {"a": {"TestListed": FAIL, "TestPortable": PASS}, "b": {}, "c": {}}
        output = self.check(packages, "synth/a TestListed\n", 0, {"synth/a.TestPortable"}, files=files)
        self.assertIn("test gate passed: 3 packages", output)

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

    def test_lines_for_tests_that_skip_themselves_are_taken_as_literally(self):
        lines = (
            "skips-itself",
            "skips-itself ",
            "skips-itself synth/a",
            "skips-itself  synth/a TestListed",
            "skips-itself\tsynth/a TestListed",
            " skips-itself synth/a TestListed",
            "Skips-itself synth/a TestListed",
            "skips-itself: synth/a TestListed",
            "skips_itself synth/a TestListed",
            "skips synth/a TestListed",
            "skip synth/a TestListed",
            "skips-itself synth/a TestListed ",
            "skips-itself synth/a TestListed # reason",
            "skips-itself synth/a TestListed requires docker",
            "skips-itself synth/a Test.*",
            "skips-itself synth/a ^TestListed$",
            "skips-itself synth/a TestListed/su|b",
            "skips-itself synth/a TestListed/sub#01",
            "skips-itself synth/a testListed",
            "skips-itself skips-itself synth/a TestListed",
            "synth/a skips-itself TestListed",
            "synth/a TestListed skips-itself",
            "fails synth/a TestListed",
        )
        for line in lines:
            with self.subTest(line=line):
                self.refused("# header\n" + line + "\n", NOT_AN_ENTRY, before_any_go_command=True)
        with self.subTest(line="repeated"):
            for line in ("skips-itself synth/a TestPortable", "skips-itself synth/a TestPortable/sub"):
                self.refused(
                    line + "\n" + line + "\n", "line 2 repeats a line", before_any_go_command=True
                )
        # One test cannot be listed as failing and as skipping itself, and
        # what lies inside an entry does not run in the gate.
        for first, second in (
            ("synth/a TestListed", "skips-itself synth/a TestListed"),
            ("synth/a TestListed", "skips-itself synth/a TestListed/sub"),
            ("synth/a TestListed/sub", "skips-itself synth/a TestListed"),
            ("synth/a TestListed/sub", "skips-itself synth/a TestListed/sub"),
            ("synth/a TestListed/sub", "skips-itself synth/a TestListed/sub/deeper"),
            ("synth/a TestListed/sub/deeper", "skips-itself synth/a TestListed/sub"),
        ):
            for listing in (first + "\n" + second + "\n", second + "\n" + first + "\n"):
                with self.subTest(listing=listing):
                    self.refused(
                        "skips-itself synth/b TestOther\n" + listing,
                        "line 3: ",
                        before_any_go_command=True,
                    )
                    self.refused(listing, OVERLAPS_AN_ENTRY, before_any_go_command=True)
        # Checked against the module like an entry.
        self.refused(
            "skips-itself synth/zzz TestListed\n",
            "listed package is not a package of this module: synth/zzz",
        )
        for line in ("synth/a TestMissing", "synth/c TestListed", "synth/a TestMissing/sub"):
            with self.subTest(line=line):
                package, path = line.split(" ")
                reason = "listed test is not defined in package %s: %s" % (
                    package,
                    path.split("/")[0],
                )
                self.refused("skips-itself " + line + "\n", reason)
                self.refused("synth/a TestListed\nskips-itself " + line + "\n", reason)
        both = {
            "a/code.go": "package a\n",
            "a/internal_test.go": test_file("a", "a", {"TestSkips": SKIP}),
            "a/external_test.go": test_file("a_test", "a", {"TestSkips": PASS}),
        }
        self.refused(
            "skips-itself synth/a TestSkips\n",
            "listed test TestSkips is defined 2 times in package synth/a",
            packages={},
            files=both,
        )

    def test_lines_of_both_kinds_that_only_look_alike_are_accepted(self):
        # The same name in another package, and names that only start alike.
        packages = {
            "a": {"TestListed": FAIL, "TestListedToo": SKIP},
            "b": {"TestListed": SKIP},
        }
        listing = (
            "synth/a TestListed\n"
            "skips-itself synth/a TestListedToo\n"
            "skips-itself synth/b TestListed\n"
        )
        for listing in (listing, "".join(reversed(listing.splitlines(True)))):
            with self.subTest(listing=listing):
                self.check(packages, listing, 0, {"synth/a.TestListedToo", "synth/b.TestListed"})

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
            whole={
                "synth/a.TestListed",
                "synth/a.TestPortable",
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_wrong_tool",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/a.TestPreflight/accepts_exact_tool",
                "synth/b.TestListed",
                "synth/b.TestOther",
            },
        )
        self.stale(output)
        self.together(output)
        self.wide(output)
        self.assertIn("still fails: synth/a TestListed\n", output)
        self.assertIn("still fails: synth/a TestPreflight/rejects_missing_tool\n", output)
        self.assertIn("still fails: synth/b TestListed\n", output)
        self.assertIn(
            "all 3 listed tests still fail on this host, each in a run of its own and in "
            "the run of its package\n",
            output,
        )
        self.assertNotIn("::error::", output)
        # One run of each listed package as a whole, with nothing skipped.
        self.package_runs(output, "synth/a", "synth/b")
        self.assertIn(
            "::group::Run of synth/a with nothing skipped, for its 2 listed tests\n", output
        )
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
                # In the run of the package both fail.
                self.together(output)
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
        output = self.check(
            BASE,
            "synth/b TestListed\n",
            1,
            {"synth/b.TestListed"},
            whole={"synth/b.TestListed", "synth/b.TestOther"},
        )
        self.stale(output, ("it passes", "synth/b TestListed"))
        self.together(output, ("it passes", "synth/b TestListed"))

    def test_listed_test_that_skips_itself_is_named(self):
        packages = {"a": {"TestListed": SKIP}}
        output = self.check(packages, "synth/a TestListed\n", 1, {"synth/a.TestListed"})
        self.stale(output, ("it skips itself", "synth/a TestListed"))
        self.together(output, ("it skips itself", "synth/a TestListed"))

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
        no_longer = (
            ("it passes", "synth/a TestNowPasses"),
            ("it skips itself", "synth/a TestSkips"),
            ("it passes", "synth/b TestListed"),
        )
        self.stale(output, *no_longer)
        self.together(output, *no_longer)
        self.assertIn("still fails: synth/a TestListed\n", output)

    def test_listed_subtest_that_passes_is_named(self):
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT}},
            "synth/a TestPreflight/accepts_exact_tool\n",
            1,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/accepts_exact_tool"},
        )
        self.stale(output, ("it passes", "synth/a TestPreflight/accepts_exact_tool"))
        self.together(output, ("it passes", "synth/a TestPreflight/accepts_exact_tool"))

    def test_listed_subtest_that_does_not_run_is_named(self):
        # A failing sibling makes the parent fail. The entry itself still has
        # to fail.
        output = self.check(
            {"a": {"TestPreflight": PREFLIGHT, "TestListed": FAIL}},
            "synth/a TestPreflight/no_such\n" + LISTED_SUBTEST + "synth/a TestListed\n",
            1,
            {
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/a.TestListed",
            },
        )
        self.stale(output, ("it did not run", "synth/a TestPreflight/no_such"))
        self.together(output, ("it did not run", "synth/a TestPreflight/no_such"))
        # TestListed is the last test of the package and fails. The run of
        # the package came to its end, so no test stopped it, and there is
        # no second run for the entry that did not run.
        self.package_runs(output, "synth/a")

    def test_listed_subtest_that_does_not_run_under_a_failing_parent_is_named(self):
        output = self.check(
            {"a": {"TestPreflight": [("first", FAIL)]}},
            "synth/a TestPreflight/first/no_such\n",
            1,
            {"synth/a.TestPreflight", "synth/a.TestPreflight/first"},
        )
        self.stale(output, ("it did not run", "synth/a TestPreflight/first/no_such"))
        self.together(output, ("it did not run", "synth/a TestPreflight/first/no_such"))

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
        self.together(output, ("it passes", "synth/a TestPreflight/accepts_exact_tool"))
        self.assertIn("still fails: synth/a TestPreflight/rejects_missing_tool\n", output)

    def test_listed_test_that_stops_the_test_binary_does_not_hide_the_next(self):
        # A panic or an exit ends the test binary. Every entry has a run of
        # its own, so the entries after it are judged all the same. The run
        # of the package does not get to them, so the package runs once
        # more, without the listed test that stopped it.
        for how in (PANIC, EXIT):
            with self.subTest(how=how):
                packages = {"a": {"TestStops": how, "TestAfter": FAIL, "TestLast": PASS}}
                listing = "synth/a TestStops\nsynth/a TestAfter\nsynth/a TestLast\n"
                everything = {"synth/a.TestStops", "synth/a.TestAfter", "synth/a.TestLast"}
                output = self.check(packages, listing, 1, everything, whole=everything)
                self.stale(output, ("it passes", "synth/a TestLast"))
                self.together(output, ("it passes", "synth/a TestLast"))
                self.package_runs(output, "synth/a", "-skip '^TestStops$' synth/a")
                self.assertIn(
                    "::group::Run of synth/a without the 1 listed tests that stopped its "
                    "test binary, for the 2 listed tests that it did not get to\n",
                    output,
                )
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
                self.together(output)
                self.package_runs(output, "synth/a", "-skip '^TestStops$' synth/a")
            with self.subTest(how=how, stops="a listed subtest"):
                # "first" failed before "stops" started. It did not stop
                # the test binary, and the second run does not leave it out.
                packages = {"a": {"TestP": [("first", FAIL), ("stops", how)], "TestAfter": FAIL}}
                listing = "synth/a TestP/first\nsynth/a TestP/stops\nsynth/a TestAfter\n"
                everything = {
                    "synth/a.TestP",
                    "synth/a.TestP/first",
                    "synth/a.TestP/stops",
                    "synth/a.TestAfter",
                }
                output = self.check(packages, listing, 0, everything, whole=everything)
                self.package_runs(output, "synth/a", "-skip '^TestP$/^stops$' synth/a")

    def test_only_the_listed_test_that_stopped_the_test_binary_is_left_out(self):
        # TestAfter fails only after TestHostBound in the same process, and
        # TestStops between them ends the test binary. The second run of the
        # package leaves out TestStops alone. If it also left out
        # TestHostBound, which failed before, TestAfter would pass there.
        listing = "synth/a TestHostBound\nsynth/a TestStops\nsynth/a TestAfter\n"
        everything = {"synth/a.TestHostBound", "synth/a.TestStops", "synth/a.TestAfter"}
        for how in (PANIC, EXIT):
            with self.subTest(how=how):
                body = STOPS_BETWEEN_TWO_THAT_SHARE_STATE % BODY[how].strip()
                output = self.check(
                    {"a": {}},
                    listing,
                    1,
                    everything,
                    files={"a/stops_test.go": raw_test_file("a", body)},
                    whole=everything,
                )
                self.together(output)
                self.stale(output, ("it passes", "synth/a TestAfter"))
                self.package_runs(output, "synth/a", "-skip '^TestStops$' synth/a")

    def test_listed_test_that_waited_when_the_test_binary_stopped_is_judged_in_the_next_run(self):
        # TestParallel stops to run in parallel later, and TestStops ends
        # the test binary before it goes on.
        output = self.check(
            {"a": {}},
            "synth/a TestParallel\nsynth/a TestStops\n",
            0,
            {"synth/a.TestParallel", "synth/a.TestStops"},
            files={"a/parallel_test.go": raw_test_file("a", STOPS_BEFORE_A_PARALLEL_TEST)},
            whole={"synth/a.TestParallel", "synth/a.TestStops"},
        )
        self.package_runs(output, "synth/a", "-skip '^TestStops$' synth/a")
        self.assertIn(
            "::group::Run of synth/a without the 1 listed tests that stopped its test "
            "binary, for the 1 listed tests that it did not get to\n",
            output,
        )

    def test_listed_test_that_failed_before_another_went_on_did_not_stop_the_test_binary(self):
        # "stops" waits to run in parallel, "fails" fails, and then "stops"
        # goes on and ends the test binary. "fails" reported after the last
        # test had started and before the last one went on. Only "stops"
        # stopped the run, and both entries fail there.
        everything = {"synth/a.TestP", "synth/a.TestP/stops", "synth/a.TestP/fails"}
        output = self.check(
            {"a": {}},
            "synth/a TestP/stops\nsynth/a TestP/fails\n",
            0,
            everything,
            files={"a/parallel_test.go": raw_test_file("a", STOPS_AFTER_A_SUBTEST_FAILED)},
            whole=everything,
        )
        self.package_runs(output, "synth/a")
        self.assertIn("still fails: synth/a TestP/stops\n", output)

    def test_two_listed_tests_that_ran_side_by_side(self):
        listing = "synth/a TestSideA\nsynth/a TestSideB\n"
        everything = {"synth/a.TestSideA", "synth/a.TestSideB"}
        fails = BODY[FAIL].strip()
        # Both fail. The run of the package came to its end.
        files = {
            "a/main_test.go": TWO_AT_A_TIME,
            "a/side_test.go": raw_test_file("a", RUN_SIDE_BY_SIDE % (fails, fails)),
        }
        output = self.check({"a": {}}, listing, 0, everything, files=files, whole=everything)
        self.package_runs(output, "synth/a")
        # TestSideA ends the test binary while TestSideB is running. The
        # run does not show which of the two stopped it, so it does not
        # show that either of them fails there. Both are named.
        files["a/side_test.go"] = raw_test_file(
            "a", RUN_SIDE_BY_SIDE % (BODY[EXIT].strip(), "select {}")
        )
        output = self.check({"a": {}}, listing, 1, everything, files=files, whole=everything)
        beside = (
            "another listed test was running with it when the test binary stopped, and "
            "nothing shows which of them stopped it"
        )
        self.together(output, (beside, "synth/a TestSideA"), (beside, "synth/a TestSideB"))
        self.stale(output)
        self.package_runs(output, "synth/a")

    def test_test_binary_stopped_by_a_test_that_is_not_listed(self):
        # The run of the package does not get to TestAfter, and no listed
        # test stopped it: TestListed failed before TestStops started.
        # Nothing shows that TestAfter fails there, so it is named. The
        # gating step fails on TestStops in any case.
        for how in (PANIC, EXIT):
            with self.subTest(how=how):
                packages = {"a": {"TestListed": FAIL, "TestStops": how, "TestAfter": FAIL}}
                output = self.check(
                    packages,
                    "synth/a TestListed\nsynth/a TestAfter\n",
                    1,
                    {"synth/a.TestListed", "synth/a.TestAfter"},
                    whole={"synth/a.TestListed", "synth/a.TestStops"},
                )
                self.together(output, ("it did not run", "synth/a TestAfter"))
                self.stale(output)
                self.package_runs(output, "synth/a")

    def test_listed_test_that_passes_in_the_run_of_its_package_is_named(self):
        # Alone, TestListed fails for want of what TestAPrepares leaves
        # behind. In the gate TestAPrepares runs, so the gate skips a test
        # that would pass there. Only the run of the package shows that.
        output = self.check(
            {"a": {}},
            "synth/a TestListed\n",
            1,
            {"synth/a.TestListed"},
            files={"a/order_test.go": raw_test_file("a", PASSES_ONLY_AFTER_ANOTHER_TEST)},
            whole={"synth/a.TestAPrepares", "synth/a.TestListed"},
        )
        self.together(output, ("it passes", "synth/a TestListed"))
        self.stale(output)
        self.assertIn("still fails: synth/a TestListed\n", output)
        self.assertNotIn("all 1 listed tests still fail", output)

    def test_listed_parallel_subtest_that_did_not_get_to_run_is_named(self):
        # In its own go test the listed subtest starts, stops to run in
        # parallel later, and the test binary ends before it goes on. Its
        # body did not run, so nothing shows that it fails. In the run of
        # the package it passes.
        output = self.check(
            {"a": {}},
            "synth/a TestP/reg\n",
            1,
            {"synth/a.TestP"},
            files={"a/parallel_test.go": raw_test_file("a", STOPS_BEFORE_ITS_PARALLEL_SUBTEST)},
            whole={"synth/a.TestP", "synth/a.TestP/reg"},
        )
        self.stale(
            output,
            (
                "it did not get to run: it waited to run in parallel when the test binary "
                "stopped",
                "synth/a TestP/reg",
            ),
        )
        self.together(output, ("it passes", "synth/a TestP/reg"))

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
        self.assertEqual(ran.whole, {"synth/b.TestListed"}, output)
        self.stale(output, ("it passes", "synth/b TestListed"))
        self.together(output, ("it passes", "synth/b TestListed"))
        self.assertIn(
            "::error::listed tests check failed: no test of synth/a started\n", output
        )
        # A test binary that runs nothing only in the go test of one entry.
        status, ran, output = run_gate(
            "still-failing",
            {"a": {"TestListed": FAIL, "TestOther": FAIL}, "b": {"TestListed": PASS}},
            "synth/a TestListed\nsynth/a TestOther\nsynth/b TestListed\n",
            files={"a/main_test.go": RUNS_NOTHING_FOR_CHOSEN_TESTS % "a"},
        )
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/b.TestListed"}, output)
        self.assertEqual(
            ran.whole, {"synth/a.TestListed", "synth/a.TestOther", "synth/b.TestListed"}, output
        )
        self.stale(output, ("it passes", "synth/b TestListed"))
        self.together(output, ("it passes", "synth/b TestListed"))
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
        # It stopped the run of the package too, and no entry is left for a
        # second run.
        self.package_runs(output, "synth/a")
        # The same for a parallel test that ends the test binary after it
        # has gone on. It is not one that still waited.
        output = self.check(
            {"a": {}},
            listing,
            0,
            {"synth/a.TestListed"},
            files={"a/parallel_test.go": raw_test_file("a", STOPS_AFTER_IT_WENT_ON)},
            whole={"synth/a.TestListed"},
        )
        self.assertIn("still fails: synth/a TestListed\n", output)
        status, ran, output = run_gate("still-failing", packages, listing, go=ZERO_STATUS_GO)
        self.assertEqual(status, 1, output)
        self.assertEqual(ran, {"synth/a.TestListed"}, output)
        self.stale(output, ("it did not run", "synth/a TestListed"))
        self.together(output, ("it did not run", "synth/a TestListed"))

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
            whole={"synth/a.TestQuiet"},
        )
        self.stale(output, ("it passes", "synth/a TestQuiet"))
        self.assertNotIn("(cached)", output)

    def test_runs_only_the_listed_tests(self):
        packages = {
            "a": {"TestListed": FAIL, "TestListedV2": FAIL, "TestPreflight": PREFLIGHT},
            "b": {"TestListed": FAIL},
        }
        # The go test of the entry runs the entry alone. The run of the
        # package runs every test of that package, and no other package.
        self.check(
            packages,
            "synth/a TestListed\n",
            0,
            {"synth/a.TestListed"},
            whole={
                "synth/a.TestListed",
                "synth/a.TestListedV2",
                "synth/a.TestPreflight",
                "synth/a.TestPreflight/rejects_wrong_tool",
                "synth/a.TestPreflight/rejects_missing_tool",
                "synth/a.TestPreflight/accepts_exact_tool",
            },
        )


class ListedSubtestStandsForItselfAlone(GateCase):
    """An entry for a subtest must be the only test under its path.

    go test reads a test path as the start of a path. The skip for TestP/reg
    also covers every test whose path starts with "TestP/reg/". The gating
    step fails when it skips such a test (GateShowsEveryTestItSkipped). This
    step refuses the entry when its own run starts one. That also holds for
    the subtests of the listed subtest itself, which do not start in the
    gate: the entry has to name the narrowest test that fails.
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

    def test_subtests_that_a_listed_subtest_does_not_reach_are_part_of_it(self):
        # The listed "reg" fails before it starts its own subtest "custody",
        # so the run of the entry does not show that subtest. It is part of
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

    def test_the_module_is_type_checked_for_macos(self):
        # Some test files of the module build only on macOS. The Linux
        # runner never compiles them in the other steps, so a change that
        # breaks their build would pass. This step type-checks them. It
        # does not run them.
        commands = [line[len("run: "):] for line in self.lines if line.startswith("run: ")]
        vets = [command for command in commands if "go vet" in command]
        self.assertEqual(vets, ["go vet ./...", "GOOS=darwin GOARCH=arm64 go vet ./..."])

    def test_the_go_build_cache_is_not_restored(self):
        self.assertIn("cache: false", self.lines)
        self.assertEqual([line for line in self.lines if line.startswith("cache:")], ["cache: false"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
