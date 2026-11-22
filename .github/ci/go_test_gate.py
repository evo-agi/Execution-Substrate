#!/usr/bin/env python3
"""CI test gate for this Go module.

Usage, from the module root:

    python3 -I -B .github/ci/go_test_gate.py gate LIST
    python3 -I -B .github/ci/go_test_gate.py still-failing LIST

LIST is a text file naming the tests that cannot pass on a CI runner for host
reasons. It has two kinds of lines. An entry names a test that fails on the
runner. It is one line holding exactly a package import path, one space and
a test path:

    execution-substrate/es/app TestExample
    execution-substrate/es/app TestExample/rejects_a_missing_tool

A line for a test that skips itself on the runner is the word "skips-itself",
one space, and the same two things:

    skips-itself execution-substrate/es/app TestNeedsAService

A test path is a top-level test name, or the path that go test prints for a
subtest: that name and one or more further parts, joined by "/". go test
prints a space in a subtest name as "_", and it joins a subtest to its
parent with "/" whether or not the subtest's own name holds a "/". Empty
lines and lines whose first character is "#" are ignored. Every other line
must be of one of the two kinds.

A test name may hold only ASCII letters, digits and underscores, and every
further part of a test path the same plus "-", so an entry can never act as
a regular expression. A line applies only to the package it names, and it
stands for one test or one subtest of it:

  - the package must be a package of this module;
  - go test must list the top-level test name exactly once for that package.
    A name defined in both the internal and the external test package of one
    directory is listed twice, and one entry would skip both;
  - no entry may lie inside another entry of the same package;
  - an entry for a whole test stands for that test with all of its subtests;
  - an entry for a subtest must stand for that subtest alone. go test reads
    a test path as the start of a path. The skip for TestA/x therefore also
    covers every test whose path starts with "TestA/x/": a subtest of x, and
    a subtest of TestA whose own name is "x/...". So a listed subtest must
    have no subtests of its own and no such neighbour. Otherwise the entry
    has to name a narrower subtest, or the whole test;
  - a line for a test that skips itself stands for exactly the test or
    subtest it names. It must not name an entry, lie inside one or hold
    one: what lies inside an entry does not run in the gate.

gate
    Checks the list, then runs every package of the module. A package with
    entries runs on its own with its own entries skipped. All other packages
    run with nothing skipped. For every package the gate then checks what
    go test reported:

      - Every top-level test that go test lists for the package and that is
        not an entry reported a verdict, and the testing package wrote the
        PASS line with which it closes a run of the tests. So a test binary
        that runs none of its tests, or only some, fails the gate.
      - The tests and subtests that skipped themselves are exactly the ones
        that LIST names with "skips-itself". A test that skips itself and
        is not listed fails the gate. So does a listed one that passes,
        fails or does not run: its line has to go. The log names every test
        that skipped itself, with what it wrote.

    The gate also writes which tests ran beside each listed subtest.

    A test that go test skips leaves no trace in its output. So a package
    with an entry for a subtest, once it has passed, runs a second time with
    the same entries skipped: the observed run described below. That run
    has to pass like the first, and the tests that go test skipped in it
    have to be exactly the entries of that package, each of them once. A
    skipped test that is not an entry is named, and so is an entry that was
    not skipped.

    Exits 0 only if every run and every check passes.

still-failing
    Checks the list, then judges every entry twice, in the package it names:
    in a run of that whole package with nothing skipped, and in a go test of
    its own. Exits 0 only if every entry fails in both and stands for itself
    alone. An entry that passes, skips itself or does not run in one of the
    two no longer belongs in the list. In a run of its own a test can fail
    only for want of what another test of its package leaves behind, and in
    the run of its package it can fail only because of what another listed
    test leaves behind. An entry for a subtest whose own run also starts
    another test covers more than itself. Each such entry is named, and the
    status is 1.

    An entry fails in a run only if the testing package reported its
    failure there. A test that was running when the test binary stopped
    has reported nothing: another test, a goroutine that an earlier test
    left behind or the time limit of go test may have stopped the binary,
    and the test might have passed. So a test that ends the process
    without reporting, for example with os.Exit or log.Fatal, cannot be
    listed.

    The run of a package has to come to its end: the testing package writes
    a closing line then. A run that does not was stopped. A listed test
    that panics reports its failure and ends the process, so it accounts
    for the stop if it reported its failure after the last test had started
    or gone on. The package then runs once more without the listed tests
    that did so, for the entries that have no verdict yet, and so on until
    a run comes to its end. A run that stops with no such listed test fails
    the step, whatever the entries reported before: something that the list
    does not name stopped it. The gate cannot tell a panic of a listed test
    from a stop that follows directly on its failure. In both the test
    reported its own failure, and the run without it shows whether the
    package still stops.

The observed run
    go test decides in one place whether -skip drops a test: in the function
    fullName in src/testing/match.go of the Go standard library. Every
    test and every subtest goes through it before it starts. For the
    observed run the gate copies that file and adds one call at the place
    where a test is dropped, and the function that the call names. The
    function appends the name of the dropped test to a file. go test gets
    the copy through -overlay, so the test binary of that one run is built
    with it. The installed toolchain is not changed, and no other run uses
    the copy.

    The copy is made from the file of the toolchain that runs the tests.
    That toolchain has to be the Go version in OBSERVED_GO_VERSION, and its
    file has to have the SHA-256 in MATCH_GO_SHA256. Otherwise the gate
    stops with status 1 before any test runs. So a new Go version needs a
    review of how its testing package skips tests, and new values here in
    the same change.

    This is what makes an entry for a subtest stand for that subtest alone.
    No pattern of go test skips TestA/x and not a neighbour named "x/...",
    and no run of x can show a neighbour that TestA starts only when x did
    not fail, for example after

        if !t.Run("x", ...) { return }

    In the gate x is skipped, so TestA goes on and reaches that neighbour,
    go test drops it with x, and the observed run writes its name down.
    What a test does not start is not skipped. A subtest that the listed x
    would start itself is part of x, and x does not run in the gate.

    The gate takes the record, like the output of go test, as the testing
    package wrote it. A test binary that a test starts with a -test.skip of
    its own writes into the same record, and the gate then fails. Nothing
    here is a defence against a test that forges the record or that output.

Exit status: 0 on success, 1 when a Go command or a check of a run fails, 2
when the list or the command line is wrong. No test has run when the status
is 2.
"""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

# One entry: a package import path, one space, a test path. Every part of the
# test path is letters, digits and underscores (a part after the first may
# also hold "-"), so it has no meaning as a regular expression beyond its own
# text.
# The package is accepted only if it is exactly one of the import paths that
# "go list ./..." prints, so it cannot be a package pattern either.
ENTRY = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./-]*) (Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_-]+)*)"
)

# A line for a test that skips itself: this word, one space and an entry.
SELF_SKIP = "skips-itself"
SKIP_LINE = re.compile(re.escape(SELF_SKIP) + " " + ENTRY.pattern)

MODES = ("gate", "still-failing")

# The actions with which "go test -json" reports the end of a test.
VERDICTS = ("pass", "fail", "skip")

# The observed run. See "The observed run" above.
#
# The Go version whose testing package was read for it, and the SHA-256 of
# src/testing/match.go in that version.
OBSERVED_GO_VERSION = "go1.26.5"
MATCH_GO_SHA256 = "f28418759ed48c72821b5ecc3700041b74151108557618f50d355ea98a1bbebe"
# The one place in that file where a test is dropped because -skip matches
# it, and the same place with the recording call added.
SKIP_BRANCH = "\tif skip && !partialSkip {\n\t\treturn name, false, false\n\t}\n"
RECORDING_SKIP_BRANCH = (
    "\tif skip && !partialSkip {\n"
    "\t\tgoTestGateRecordSkipped(name)\n"
    "\t\treturn name, false, false\n"
    "\t}\n"
)
# The environment variable that names the file for the dropped names. The
# test binary reads it once, when it starts, so a test that changes its
# environment does not switch the recording off. The file has to exist: a
# name that cannot be written ends the test binary.
SKIPPED_NAMES = "GO_TEST_GATE_SKIPPED_NAMES"
RECORDER = """
// Added by .github/ci/go_test_gate.py for its observed run. Not part of Go.
var goTestGateSkippedNames = os.Getenv("%s")

func goTestGateRecordSkipped(name string) {
	if goTestGateSkippedNames == "" {
		return
	}
	file, err := os.OpenFile(goTestGateSkippedNames, os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		_, err = file.WriteString(name + "\\n")
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		panic("go_test_gate: cannot record the skipped test " + name + ": " + err.Error())
	}
}
""" % SKIPPED_NAMES


class ListError(Exception):
    """The list or the command line is wrong. Exit status 2."""


class GoError(Exception):
    """A Go command that the gate depends on failed. Exit status 1."""


def emit(text):
    """Write one line to the log, whatever the locale of the host is."""
    sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
    sys.stdout.buffer.flush()


def inside(path, other):
    """Report whether test path "path" starts with test path "other" and a "/".

    That holds for a subtest of "other" at any depth, and for a test beside
    "other" whose own name starts with the last part of "other" and a "/".
    go test tells them apart no more than this does.
    """
    return path.startswith(other + "/")


def nearest_above(path, tests):
    """Return the longest of the given test paths that "path" is inside of.

    Returns None when there is none.
    """
    parts = path.split("/")
    for length in range(len(parts) - 1, 0, -1):
        candidate = "/".join(parts[:length])
        if candidate in tests:
            return candidate
    return None


def read_entries(path):
    """Return the list's entries and its lines for tests that skip themselves.

    Both are (package, test path) pairs, in file order.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise ListError("cannot read %s: %s" % (path, error.strerror))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ListError("%s is not valid UTF-8" % path)
    entries = []
    skips = []
    for number, line in enumerate(text.split("\n"), start=1):
        if line == "" or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        kind = entries
        if match is None:
            match = SKIP_LINE.fullmatch(line)
            kind = skips
        if match is None:
            raise ListError(
                "%s line %d is not '<package> <TestName>[/<subtest>...]' and not "
                "'%s <package> <TestName>[/<subtest>...]': %r"
                % (path, number, SELF_SKIP, line)
            )
        entry = (match.group(1), match.group(2))
        for package, other in entries:
            if package != entry[0]:
                continue
            if other == entry[1] and kind is entries:
                raise ListError("%s line %d repeats an entry: %r" % (path, number, line))
            if kind is entries and (inside(entry[1], other) or inside(other, entry[1])):
                raise ListError(
                    "%s line %d: one of %r and %r lies inside the other; "
                    "an entry must not overlap another entry"
                    % (path, number, entry[1], other)
                )
        for package, other in skips:
            if package == entry[0] and other == entry[1] and kind is skips:
                raise ListError("%s line %d repeats a line: %r" % (path, number, line))
        for package, other in skips if kind is entries else entries:
            if package != entry[0]:
                continue
            if other == entry[1] or inside(entry[1], other) or inside(other, entry[1]):
                raise ListError(
                    "%s line %d: %r and %r overlap, and one of them is an entry; a "
                    "line for a test that skips itself must not name an entry, lie "
                    "inside one or hold one" % (path, number, entry[1], other)
                )
        kind.append(entry)
    return entries, skips


def by_package(entries):
    """Group test paths under their package, keeping list order."""
    grouped = {}
    for package, path in entries:
        grouped.setdefault(package, []).append(path)
    return grouped


def exact_paths(paths):
    """Return the narrowest pattern that go test has for the given test paths.

    go test splits a -run or -skip pattern at "|" into alternatives and each
    alternative at "/" into one expression per part of the test path. Every
    part is anchored here, so "^A$/^b$" does not match A itself and not a
    subtest of A with another name. It does match every test whose path
    starts with "A/b/": go test splits the path of a test at "/" as well
    and compares only as many parts as the pattern has. No pattern is
    narrower than that, which is why the gate has an observed run that
    shows what the pattern dropped. The reading of "|" is why entries of
    one package must not overlap: go test stops at the first alternative
    that matches even in part.
    """
    return "|".join(
        "/".join("^" + part + "$" for part in path.split("/")) for path in paths
    )


def show(command, variables=None):
    """Write a command to the log, after the variables set for it alone."""
    settings = [
        "%s=%s" % (name, shlex.quote(value)) for name, value in sorted((variables or {}).items())
    ]
    emit("+ " + " ".join(settings + [shlex.join(command)]))


def run(command):
    """Run a command with its output going to the log. Return its exit status."""
    show(command)
    return subprocess.run(command).returncode


def capture(command):
    """Run a command and return its exit status and its standard output."""
    show(command)
    done = subprocess.run(command, stdout=subprocess.PIPE)
    return done.returncode, done.stdout.decode("utf-8", "replace")


class Run:
    """What "go test -json" reported for one package in one run."""

    def __init__(self):
        # The verdict (pass, fail or skip) of every test and subtest that
        # reported one.
        self.verdicts = {}
        # The tests and subtests that started.
        self.started = set()
        # The tests and subtests that reported skip, each with what it wrote.
        self.skipped = {}
        # The tests that stopped to run in parallel later and have not gone on.
        self.waiting = set()
        # Whether the testing package wrote the PASS line that closes a run
        # of the tests. A test binary that never runs them does not write it.
        self.closed = False
        # Whether the testing package wrote that line or the FAIL line in its
        # place. A test binary that a test stops writes neither.
        self.finished = False
        # The events that name a test are counted. "began" is the number of
        # the last one with which a test started or went on, and "reported"
        # holds for every verdict the number of its event.
        self.events = 0
        self.began = 0
        self.reported = {}
        # How go test says the package ended: pass, fail, or skip for a
        # package without test files. None when it did not say.
        self.ended = None


def said(outputs):
    """Return in one line what a test wrote, without the lines of go test."""
    lines = [line.strip() for line in "".join(outputs).split("\n")]
    lines = [line for line in lines if line and not line.startswith(("=== ", "--- "))]
    if not lines:
        return "it wrote nothing"
    more = " [and %d more lines]" % (len(lines) - 1) if len(lines) > 1 else ""
    return lines[0][:240] + more


def go_test_json(arguments, variables=None):
    """Run "go test -json" with the given arguments.

    Writes to the log what plain "go test" would: everything that belongs to
    no test, and the output of every top-level test that does not end with
    pass or skip, its subtests included. Returns the exit status and a Run
    for every package that go test reported on, by import path. variables
    holds environment variables to set for this command alone.
    """
    command = ["go", "test", "-json"] + arguments
    show(command, variables)
    environment = None
    if variables:
        environment = dict(os.environ)
        environment.update(variables)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, env=environment)
    runs = {}
    pending = {}
    wrote = {}
    for raw in process.stdout:
        line = raw.decode("utf-8", "replace")
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict):
            emit(line.rstrip("\n"))
            continue
        package = event.get("Package")
        if not isinstance(package, str):
            package = ""
        result = runs.setdefault(package, Run())
        verdicts, started = result.verdicts, result.started
        test = event.get("Test")
        action = event.get("Action")
        output = event.get("Output")
        if not isinstance(output, str):
            output = ""
        if not isinstance(test, str) or test == "":
            if output:
                emit(output.rstrip("\n"))
            if output == "PASS\n":
                result.closed = True
            if output in ("PASS\n", "FAIL\n"):
                result.finished = True
            if action in VERDICTS:
                result.ended = action
            continue
        top = test.split("/")[0]
        started.add(test)
        result.events += 1
        if action in ("run", "cont"):
            result.began = result.events
        if output:
            pending.setdefault((package, top), []).append(output)
            wrote.setdefault((package, test), []).append(output)
        if action == "pause":
            result.waiting.add(test)
        if action == "cont":
            result.waiting.discard(test)
        if action in VERDICTS:
            verdicts[test] = action
            result.reported[test] = result.events
            own = wrote.pop((package, test), [])
            if action == "skip":
                result.skipped[test] = said(own)
            if test == top:
                kept = pending.pop((package, top), [])
                if action == "fail" and kept:
                    emit("".join(kept).rstrip("\n"))
    status = process.wait()
    for key in sorted(pending):
        # A test that began and reported no verdict: the test binary stopped.
        emit("".join(pending[key]).rstrip("\n"))
    return status, runs


def one(runs, package):
    """Return what a go test run reported for the package, or an empty Run."""
    return runs.get(package) or Run()


def module_packages():
    """Return every package import path of the module in the current directory."""
    status, output = capture(["go", "list", "./..."])
    if status != 0:
        raise GoError("go list ./... failed")
    packages = [line for line in output.split("\n") if line != ""]
    if not packages:
        raise GoError("go list ./... named no package")
    if len(set(packages)) != len(packages):
        raise GoError("go list ./... named a package twice")
    return packages


def top_level_tests(package):
    """Return the top-level test names that go test lists for the package.

    A name appears once for each definition. Returns None when the test
    binary could not be listed, for example because the package does not
    compile. Listing runs no test.
    """
    status, output = capture(["go", "test", "-list", "^Test", package])
    if status != 0:
        return None
    return [line for line in output.split("\n") if line.startswith("Test")]


def check_list(grouped, declared, packages):
    """Check the lines against the module. Raise ListError on a wrong line.

    grouped holds the entries and declared the lines for tests that skip
    themselves, both by package. Returns, for each package with a line, the
    top-level test names of its test binary, or None where that binary could
    not be listed.
    """
    lines = {}
    for kind in (grouped, declared):
        for package, paths in kind.items():
            lines.setdefault(package, []).extend(paths)
    for package in lines:
        if package not in packages:
            raise ListError("listed package is not a package of this module: %s" % package)
    listings = {}
    for package, paths in lines.items():
        listed = top_level_tests(package)
        listings[package] = listed
        if listed is None:
            continue
        for path in paths:
            name = path.split("/")[0]
            count = listed.count(name)
            if count == 0:
                raise ListError(
                    "listed test is not defined in package %s: %s" % (package, name)
                )
            if count != 1:
                raise ListError(
                    "listed test %s is defined %d times in package %s (in its "
                    "internal and its external test package); one entry would "
                    "skip all of them" % (name, count, package)
                )
    return listings


def check_gated_run(package, paths, skips, listed, result, list_path, beside=True):
    """Compare what go test reported for a gated run of a package with the list.

    paths holds the entries of the package and skips its lines for tests
    that skip themselves. Returns the problems found. Unless "beside" is
    false, writes one line per listed subtest saying which tests ran beside
    it: the tests with the same nearest test above them among those that
    ran. It then also writes every test that skipped itself. A part of a
    listed path need not be a test, because the name of a subtest may itself
    hold a "/". So only the top-level test of a listed subtest is required
    to have run here. The observed run requires the listed subtest itself to
    be reached, and still-failing requires it to start.
    """
    verdicts = result.verdicts
    if result.ended not in ("pass", "skip"):
        return ["%s: go test did not report that the package passed" % package]
    problems = []
    if result.ended == "pass" and not result.closed:
        problems.append(
            "%s: the test binary ended without the PASS line that the testing "
            "package writes when it has run the tests. A TestMain that does not "
            "call m.Run switches every test of its package off" % package
        )
    whole = {path for path in paths if "/" not in path}
    missing = sorted(
        {name for name in listed if name not in whole and name not in verdicts}
    )
    if missing:
        problems.append(
            "%s: tests that are not listed did not run: %s" % (package, ", ".join(missing))
        )
    for path in paths if beside else ():
        parent = nearest_above(path, verdicts)
        if parent is None:
            # A whole test, or a subtest of a test reported as missing above.
            continue
        neighbours = sorted(
            test for test in verdicts if nearest_above(test, verdicts) == parent
        )
        emit(
            "%s: %s ran without the listed %s; beside it ran: %s"
            % (
                package,
                parent,
                path[len(parent) + 1 :],
                ", ".join(
                    "%s %s" % (test[len(parent) + 1 :], verdicts[test]) for test in neighbours
                )
                or "nothing",
            )
        )
    if beside and result.skipped:
        emit("::group::%s: %d tests skipped themselves" % (package, len(result.skipped)))
        for test in sorted(result.skipped):
            emit("skips itself: %s %s: %s" % (package, test, result.skipped[test]))
        emit("::endgroup::")
    unlisted = sorted(test for test in result.skipped if test not in skips)
    for test in unlisted:
        emit(
            "::error::test skips itself and is not listed: %s %s (%s). A test that "
            "cannot run on this host needs the line '%s %s %s' in %s, with its "
            "reason in a comment. A test that can run here must not skip itself."
            % (package, test, result.skipped[test], SELF_SKIP, package, test, list_path)
        )
    stale = [path for path in skips if path not in result.skipped]
    for path in stale:
        emit(
            "::error::listed test no longer skips itself on this host (%s): %s %s. "
            "Delete its line from %s, or correct the line."
            % (
                "it passes" if verdicts.get(path) == "pass" else "it did not run",
                package,
                path,
                list_path,
            )
        )
    if unlisted or stale:
        problems.append(
            "%s: the tests that skipped themselves are not exactly the listed ones" % package
        )
    return problems


def recording_overlay(directory):
    """Write what the observed run needs into the directory.

    Returns the path of the overlay file for go test. It puts a copy of
    src/testing/match.go that records every test dropped by -skip in the
    place of the file of the toolchain. Raises GoError unless the toolchain
    is the one this was written against.
    """
    status, output = capture(["go", "env", "GOVERSION", "GOROOT"])
    answers = output.split("\n")
    if status != 0 or len(answers) != 3 or answers[2] != "" or not os.path.isabs(answers[1]):
        raise GoError("go env GOVERSION GOROOT failed")
    version, goroot = answers[0], answers[1]
    if version != OBSERVED_GO_VERSION:
        raise GoError(
            "the observed run is written against %s, and the go command is %s. Review "
            "how the testing package of that version skips tests, then set "
            "OBSERVED_GO_VERSION and MATCH_GO_SHA256 in go_test_gate.py"
            % (OBSERVED_GO_VERSION, version)
        )
    stock = os.path.join(goroot, "src", "testing", "match.go")
    try:
        with open(stock, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise GoError("cannot read %s: %s" % (stock, error.strerror))
    found = hashlib.sha256(raw).hexdigest()
    if found != MATCH_GO_SHA256:
        raise GoError(
            "%s is not the file of %s that the observed run is written against: its "
            "SHA-256 is %s, not %s" % (stock, OBSERVED_GO_VERSION, found, MATCH_GO_SHA256)
        )
    text = raw.decode("utf-8")
    if text.count(SKIP_BRANCH) != 1:
        raise GoError("%s does not drop skipped tests in exactly one place" % stock)
    changed = os.path.join(directory, "match.go")
    with open(changed, "wb") as handle:
        handle.write((text.replace(SKIP_BRANCH, RECORDING_SKIP_BRANCH) + RECORDER).encode("utf-8"))
    overlay = os.path.join(directory, "overlay.json")
    with open(overlay, "w") as handle:
        json.dump({"Replace": {stock: changed}}, handle)
    return overlay


def observed_run(package, paths, skips, listed, overlay, record, list_path):
    """Run a package with entries once more and check what go test skipped.

    The test binary of this run writes the name of every test that -skip
    drops into the file "record". Returns the problems found: the run or
    its checks fail, or the names are not exactly the entries, each once.
    """
    with open(record, "wb"):
        pass
    emit("%s: observed run, with every test that -skip drops written down" % package)
    status, runs = go_test_json(
        ["-count=1", "-overlay", overlay, "-skip", exact_paths(paths), package],
        {SKIPPED_NAMES: record},
    )
    if status != 0:
        return ["the observed run of " + package]
    problems = [
        "observed run: " + problem
        for problem in check_gated_run(
            package, paths, skips, listed, one(runs, package), list_path, beside=False
        )
    ]
    try:
        with open(record, "rb") as handle:
            names = handle.read().decode("utf-8", "replace").split("\n")
    except OSError as error:
        return problems + [
            "the record of the observed run of %s cannot be read: %s"
            % (package, error.strerror)
        ]
    # Every name is written with a line end after it.
    if names.pop() != "":
        return problems + ["the record of the observed run of %s ends inside a name" % package]
    unlisted = sorted({name for name in names if name not in paths})
    for name in unlisted:
        entry = nearest_above(name, paths)
        if entry is None:
            # Not a test that an entry of this run can drop. A test binary
            # that a test starts with a -test.skip of its own writes into
            # the same record.
            emit(
                "::error::the gate skipped a test that is not listed: %s %s. No "
                "entry covers it. A test of this package ran a test binary with "
                "a -test.skip of its own." % (package, name)
            )
            continue
        emit(
            "::error::the gate skipped a test that is not listed: %s %s. The entry "
            "%s covers it as well, because go test reads a test path as the start "
            "of a path. An entry for a subtest must be the only test whose path "
            "starts with its own. In %s, name a narrower subtest, or list the "
            "whole test %s." % (package, name, entry, list_path, name.split("/")[0])
        )
    unskipped = [path for path in paths if path not in names]
    for path in unskipped:
        emit(
            "::error::the gate did not skip the listed %s %s: the observed run did "
            "not reach a test of that name, so the line skipped nothing. Correct "
            "the line in %s, or delete it." % (package, path, list_path)
        )
    repeated = sorted({name for name in names if names.count(name) != 1})
    if repeated:
        emit(
            "::error::the observed run of %s wrote down a skipped test more than "
            "once: %s" % (package, ", ".join(repeated))
        )
    if unlisted or unskipped or repeated:
        problems.append(
            "%s: the tests that go test skipped are not exactly the listed ones" % package
        )
    if not problems:
        emit(
            "%s: the observed run passed; go test skipped exactly the listed tests "
            "of this package (%d), each once" % (package, len(paths))
        )
    return problems


def gate(entries, skips, list_path):
    packages = module_packages()
    grouped = by_package(entries)
    declared = by_package(skips)
    listings = check_list(grouped, declared, packages)

    scratch = None
    if any("/" in path for _, path in entries):
        scratch = tempfile.mkdtemp(prefix="go-test-gate-")
    try:
        return gated_runs(
            packages, grouped, declared, listings, scratch, list_path, len(entries), len(skips)
        )
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)


def gated_runs(packages, grouped, declared, listings, scratch, list_path, count, skipping):
    """Run every package as "gate" describes. scratch is a directory of the
    gate's own, given when the list has an entry for a subtest."""
    overlay = None
    if scratch is not None:
        overlay = recording_overlay(scratch)

    failed = []
    for package, paths in grouped.items():
        listed = listings[package]
        if listed is None:
            # The run of this package below reports the reason.
            failed.append("go test -list for " + package)
        status, runs = go_test_json(
            ["-count=1", "-skip", exact_paths(paths), package]
        )
        if status != 0:
            failed.append(package)
            continue
        if listed is None:
            continue
        skips = declared.get(package, [])
        problems = check_gated_run(
            package, paths, skips, listed, one(runs, package), list_path
        )
        if not problems and any("/" in path for path in paths):
            problems = observed_run(
                package,
                paths,
                skips,
                listed,
                overlay,
                os.path.join(scratch, "skipped-names.txt"),
                list_path,
            )
        failed.extend(problems)

    others = [package for package in packages if package not in grouped]
    if len(others) + len(grouped) != len(packages):
        raise GoError("the packages with and without entries do not add up")
    for package in others:
        # The packages with a line were listed when the list was checked.
        if package not in listings:
            listings[package] = top_level_tests(package)
        if listings[package] is None:
            # The run below reports the reason.
            failed.append("go test -list for " + package)
    if others:
        status, runs = go_test_json(["-count=1"] + others)
        if status != 0:
            failed.append("the packages without entries")
        for package in others:
            result = one(runs, package)
            if result.ended == "fail" or listings[package] is None:
                # go test has said so above, and the status is not 0.
                continue
            failed.extend(
                check_gated_run(
                    package, [], declared.get(package, []), listings[package], result, list_path
                )
            )

    if failed:
        emit("::error::test gate failed: " + "; ".join(failed))
        return 1
    emit(
        "test gate passed: %d packages, %d of them with skipped entries (%d entries); "
        "%d tests skipped themselves, all of them listed"
        % (len(packages), len(grouped), count, skipping)
    )
    return 0


def also_covered(path, started):
    """Return the tests that an entry covers besides the one it names.

    "started" holds the tests that started in a run of that entry alone. An
    entry for a whole test stands for the test and all of its subtests, and
    its one anchored part can start nothing else. An entry for a subtest
    stands for that subtest alone, so every other test that started inside
    its path is one that the same pattern skips in the gate.
    """
    if "/" not in path:
        return []
    return sorted(test for test in started if inside(test, path))


def subtests_note(path, verdicts, started):
    """Return a note on how the subtests of a listed whole test ended, or ""."""
    if "/" in path:
        return ""
    ended = [verdicts.get(test, "unfinished") for test in started if inside(test, path)]
    counts = [
        "%d %s" % (ended.count(how), how)
        for how in VERDICTS + ("unfinished",)
        if ended.count(how)
    ]
    return " (its subtests: %s)" % ", ".join(counts) if counts else ""


def judged(path, result):
    """Return how a listed test ended in a run: fail, pass, skip, or why not.

    Only a verdict that the testing package reported counts. A test that
    started and has none waited to run in parallel, or was running, when the
    test binary stopped. Whatever stopped it, the test did not report a
    failure of its own.
    """
    found = result.verdicts.get(path)
    if found is not None:
        return found
    if path in result.waiting:
        return "waiting"
    if path in result.started:
        return "unfinished"
    return "missing"


# How the judgements that are not "fail" read in a message.
NOT_FAILING = {
    "pass": "it passes",
    "skip": "it skips itself",
    "missing": "it did not run",
    "waiting": "it did not get to run: it waited to run in parallel when the test binary stopped",
    "unfinished": (
        "it reported no failure: the test binary stopped while it ran, and only a "
        "failure that the testing package reports counts"
    ),
}
# The same, in a few words, for the listed tests that a stopped run of their
# package left without a verdict.
NO_VERDICT = {
    "missing": "did not run",
    "waiting": "waited to run in parallel",
    "unfinished": "was running",
}


def in_the_run_of_its_package(package, paths):
    """Judge every entry of a package in a run of that whole package.

    Returns None when no test of the package started. Otherwise returns two
    values. The first holds the entries that do not fail there, each with
    how it ended. The second is None when the last run came to its end.
    When that run stopped with no listed test to account for it, the second
    holds the entries that it left without a verdict, each with its state,
    and the first does not hold them.

    The first run skips nothing. A run that does not come to its end was
    stopped: by a test that panicked or ended the process, by a goroutine
    that a test left behind, or by the time limit of go test. A listed test
    accounts for the stop if it reported its failure after the last test
    had started or gone on, as a panic does: it reports the test and ends
    the process. Then the package runs again without those listed tests,
    for the entries that have no verdict yet. That goes on until a run
    comes to its end, also when no entry is left to judge: only that run
    shows that nothing else stops the package.
    """
    not_failing = []
    left = list(paths)
    stopped = []
    while True:
        if stopped:
            emit(
                "::group::Run of %s without the %d listed tests that reported a failure "
                "as its test binary stopped: it has to come to its end, and %d listed "
                "tests have no verdict yet" % (package, len(stopped), len(left))
            )
            _, runs = go_test_json(["-count=1", "-skip", exact_paths(stopped), package])
        else:
            emit(
                "::group::Run of %s with nothing skipped, for its %d listed tests"
                % (package, len(paths))
            )
            _, runs = go_test_json(["-count=1", package])
        emit("::endgroup::")
        result = one(runs, package)
        if not result.started and not stopped:
            # For example a build failure. The output above has the reason.
            return None
        # The entries that this run left without a verdict.
        later = []
        for path in left:
            found = judged(path, result)
            if found in NO_VERDICT:
                later.append((path, found))
            elif found != "fail":
                not_failing.append((path, NOT_FAILING[found]))
        if result.finished:
            return not_failing + [(path, NOT_FAILING[found]) for path, found in later], None
        # The listed tests of this run that failed with no test starting or
        # going on after them. An entry that an earlier run judged can be
        # one of them.
        last = [
            path
            for path in paths
            if path not in stopped
            and result.verdicts.get(path) == "fail"
            and result.reported[path] > result.began
        ]
        if not last:
            return not_failing, [(path, NO_VERDICT[found]) for path, found in later]
        stopped.extend(last)
        left = [path for path, _ in later]


def still_failing(entries, skips, list_path):
    packages = module_packages()
    grouped = by_package(entries)
    listings = check_list(grouped, by_package(skips), packages)

    stale = []
    together = []
    cut_short = []
    wide = []
    failed = []
    for package, paths in grouped.items():
        if listings[package] is None:
            # The runs of this package below report the reason.
            failed.append("go test -list for " + package)
        # Alone, a listed test could fail only for want of what another test
        # of its package leaves behind.
        judgement = in_the_run_of_its_package(package, paths)
        if judgement is None:
            failed.append("no test of %s started" % package)
            continue
        not_failing, no_verdict = judgement
        together.extend((package, path, reason) for path, reason in not_failing)
        if no_verdict is not None:
            cut_short.append((package, no_verdict))
        for path in paths:
            # One go test for each entry: another listed test in the same
            # process could change what this one does.
            emit("::group::Expected failure of the listed %s %s" % (package, path))
            _, runs = go_test_json(["-count=1", "-run", exact_paths([path]), package])
            emit("::endgroup::")
            alone = one(runs, package)
            verdicts, started = alone.verdicts, alone.started
            if not started:
                # For example a build failure. The output above has the
                # reason, and the other entries of the package would meet it too.
                failed.append("no listed test of %s started" % package)
                break
            found = judged(path, alone)
            if found == "fail":
                emit(
                    "still fails: %s %s%s"
                    % (package, path, subtests_note(path, verdicts, started))
                )
            else:
                stale.append((package, path, NOT_FAILING[found]))
            others = also_covered(path, started)
            if others:
                wide.append((package, path, others))

    for package, path, reason in stale:
        emit(
            "::error::listed test no longer fails on this host (%s): %s %s. "
            "Delete its line from %s, or correct the line."
            % (reason, package, path, list_path)
        )
    for package, path, reason in together:
        emit(
            "::error::listed test does not fail in the run of its package (%s): %s %s. "
            "The gate skips a test that would not fail there. Delete its line from "
            "%s, or correct the line." % (reason, package, path, list_path)
        )
    for package, no_verdict in cut_short:
        emit(
            "::error::the run of %s stopped before its end, and no listed test "
            "accounts for it: none reported a failure as the test binary stopped. A "
            "test that is not listed, a test that ended the process without reporting "
            "a failure, or the time limit of go test stopped it. The output of that "
            "run is above. The step passes only if the run of every listed package "
            "comes to its end. Listed tests that this run left without a verdict: %s."
            % (
                package,
                ", ".join("%s (%s)" % entry for entry in no_verdict) or "none",
            )
        )
    for package, path, others in wide:
        emit(
            "::error::listed subtest is not the only test under its path: %s %s also "
            "covers %s. The gate skips them with it. An entry for a subtest must be "
            "the only test whose path starts with its own. In %s, name such a "
            "subtest, or list the whole test %s."
            % (package, path, ", ".join(others), list_path, path.split("/")[0])
        )
    if failed:
        emit("::error::listed tests check failed: " + "; ".join(failed))
    if stale or together or cut_short or wide or failed:
        return 1
    emit(
        "all %d listed tests still fail on this host, each in a run of its own "
        "and in the run of its package" % len(entries)
    )
    return 0


def main(arguments):
    if len(arguments) != 2 or arguments[0] not in MODES:
        raise ListError("usage: go_test_gate.py gate|still-failing LIST")
    entries, skips = read_entries(arguments[1])
    if arguments[0] == "gate":
        return gate(entries, skips, arguments[1])
    return still_failing(entries, skips, arguments[1])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ListError as error:
        emit("::error::test gate list: %s" % error)
        sys.exit(2)
    except GoError as error:
        emit("::error::test gate: %s" % error)
        sys.exit(1)
