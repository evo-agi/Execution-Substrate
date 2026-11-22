#!/usr/bin/env python3
"""CI test gate for this Go module.

Usage, from the module root:

    python3 -I -B .github/ci/go_test_gate.py gate LIST
    python3 -I -B .github/ci/go_test_gate.py still-failing LIST

LIST is a text file naming the tests that cannot pass on a CI runner for host
reasons. An entry is one line holding exactly a package import path, one
space and a test path:

    execution-substrate/es/app TestExample
    execution-substrate/es/app TestExample/rejects_a_missing_tool

A test path is a top-level test name, or that name followed by one or more
subtest names, joined by "/" and spelled as go test prints them (go test
prints a space in a subtest name as "_"). Empty lines and lines whose first
character is "#" are ignored. Every other line must be an entry.

A test name may hold only ASCII letters, digits and underscores, and a
subtest name the same plus "-", so an entry can never act as a regular
expression. An entry applies only to the package it names, and to exactly
one test or subtest of it:

  - the package must be a package of this module;
  - go test must list the top-level test name exactly once for that package.
    A name defined in both the internal and the external test package of one
    directory is listed twice, and one entry would skip both;
  - no entry may lie inside another entry of the same package.

gate
    Checks the list, then runs every package of the module. A package with
    entries runs on its own with exactly its own entries skipped. The gate
    then checks what really ran there: every top-level test that is not an
    entry, and the parent of every listed subtest. All other packages run
    with nothing skipped. Exits 0 only if every run and every check passes.

still-failing
    Checks the list, then runs exactly the entries, each in the package it
    names. Exits 0 only if every entry fails. An entry that passes, skips
    itself or does not run no longer belongs in the list. It is named, and
    the status is 1.

Exit status: 0 on success, 1 when a Go command or a check of a run fails, 2
when the list or the command line is wrong. No test has run when the status
is 2.
"""

import json
import re
import shlex
import subprocess
import sys

# One entry: a package import path, one space, a test path. Every element of
# the test path is letters, digits and underscores (a subtest name may also
# hold "-"), so it has no meaning as a regular expression beyond its own text.
# The package is accepted only if it is exactly one of the import paths that
# "go list ./..." prints, so it cannot be a package pattern either.
ENTRY = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./-]*) (Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_-]+)*)"
)

MODES = ("gate", "still-failing")

# The actions with which "go test -json" reports the end of a test.
VERDICTS = ("pass", "fail", "skip")


class ListError(Exception):
    """The list or the command line is wrong. Exit status 2."""


class GoError(Exception):
    """A Go command that the gate depends on failed. Exit status 1."""


def emit(text):
    """Write one line to the log, whatever the locale of the host is."""
    sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
    sys.stdout.buffer.flush()


def inside(path, other):
    """Report whether test path "path" is a subtest, at any depth, of "other"."""
    return path.startswith(other + "/")


def read_entries(path):
    """Return the list's entries as (package, test path) pairs, in file order."""
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
    for number, line in enumerate(text.split("\n"), start=1):
        if line == "" or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        if match is None:
            raise ListError(
                "%s line %d is not '<package> <TestName>[/<subtest>...]': %r"
                % (path, number, line)
            )
        entry = (match.group(1), match.group(2))
        for package, other in entries:
            if package != entry[0]:
                continue
            if other == entry[1]:
                raise ListError("%s line %d repeats an entry: %r" % (path, number, line))
            if inside(entry[1], other) or inside(other, entry[1]):
                raise ListError(
                    "%s line %d: one of %r and %r lies inside the other; "
                    "an entry must not overlap another entry"
                    % (path, number, entry[1], other)
                )
        entries.append(entry)
    return entries


def by_package(entries):
    """Group test paths under their package, keeping list order."""
    grouped = {}
    for package, path in entries:
        grouped.setdefault(package, []).append(path)
    return grouped


def exact_paths(paths):
    """Return a pattern that matches exactly the given test paths.

    go test splits a -run or -skip pattern at "|" into alternatives and each
    alternative at "/" into one expression per level of the test path. Every
    level is anchored here, so "^A$/^b$" matches subtest b of test A, not A
    itself and not A's other subtests. That reading of "|" is why entries of
    one package must not overlap: go test stops at the first alternative
    that matches even in part.
    """
    return "|".join(
        "/".join("^" + element + "$" for element in path.split("/")) for path in paths
    )


def show(command):
    emit("+ " + shlex.join(command))


def run(command):
    """Run a command with its output going to the log. Return its exit status."""
    show(command)
    return subprocess.run(command).returncode


def capture(command):
    """Run a command and return its exit status and its standard output."""
    show(command)
    done = subprocess.run(command, stdout=subprocess.PIPE)
    return done.returncode, done.stdout.decode("utf-8", "replace")


def go_test_json(arguments):
    """Run "go test -json" with the given arguments.

    Writes to the log what plain "go test" would: everything that belongs to
    no test, and the output of every top-level test that does not end with
    pass or skip, its subtests included. Returns the exit status, the verdict
    (pass, fail or skip) of every test and subtest that reported one, and the
    set of tests and subtests that started.
    """
    command = ["go", "test", "-json"] + arguments
    show(command)
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    verdicts = {}
    started = set()
    pending = {}
    for raw in process.stdout:
        line = raw.decode("utf-8", "replace")
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict):
            emit(line.rstrip("\n"))
            continue
        test = event.get("Test")
        action = event.get("Action")
        output = event.get("Output")
        if not isinstance(output, str):
            output = ""
        if not isinstance(test, str) or test == "":
            if output:
                emit(output.rstrip("\n"))
            continue
        top = test.split("/")[0]
        started.add(test)
        if output:
            pending.setdefault(top, []).append(output)
        if action in VERDICTS:
            verdicts[test] = action
            if test == top:
                kept = pending.pop(top, [])
                if action == "fail" and kept:
                    emit("".join(kept).rstrip("\n"))
    status = process.wait()
    for top in sorted(pending):
        # A test that began and reported no verdict: the test binary stopped.
        emit("".join(pending[top]).rstrip("\n"))
    return status, verdicts, started


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


def check_list(grouped, packages):
    """Check the entries against the module. Raise ListError on a wrong entry.

    Returns, for each listed package, the top-level test names of its test
    binary, or None where that binary could not be listed.
    """
    for package in grouped:
        if package not in packages:
            raise ListError("listed package is not a package of this module: %s" % package)
    listings = {}
    for package, paths in grouped.items():
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


def check_gated_run(package, paths, listed, verdicts):
    """Compare what ran in a passing gated run of a package with the list.

    Returns the problems found. Writes one line per listed subtest saying
    which other subtests of its parent ran.
    """
    problems = []
    whole = {path for path in paths if "/" not in path}
    missing = sorted(
        {name for name in listed if name not in whole and name not in verdicts}
    )
    if missing:
        problems.append(
            "%s: tests that are not listed did not run: %s" % (package, ", ".join(missing))
        )
    for path in paths:
        if "/" not in path:
            continue
        elements = path.split("/")
        ancestors = ["/".join(elements[:depth]) for depth in range(1, len(elements))]
        absent = [ancestor for ancestor in ancestors if ancestor not in verdicts]
        if absent:
            if absent[0] not in missing:
                problems.append(
                    "%s: %s did not run, so nothing shows that the subtests beside "
                    "the listed %s ran" % (package, absent[0], path)
                )
            continue
        parent = ancestors[-1]
        siblings = sorted(
            test
            for test in verdicts
            if inside(test, parent) and "/" not in test[len(parent) + 1 :]
        )
        emit(
            "%s: %s ran without its listed subtest %s; its other subtests: %s"
            % (
                package,
                parent,
                elements[-1],
                ", ".join(
                    "%s %s" % (test[len(parent) + 1 :], verdicts[test]) for test in siblings
                )
                or "none",
            )
        )
    return problems


def gate(entries):
    packages = module_packages()
    grouped = by_package(entries)
    listings = check_list(grouped, packages)

    failed = []
    for package, paths in grouped.items():
        listed = listings[package]
        if listed is None:
            # The run of this package below reports the reason.
            failed.append("go test -list for " + package)
        status, verdicts, _ = go_test_json(
            ["-count=1", "-skip", exact_paths(paths), package]
        )
        if status != 0:
            failed.append(package)
        elif listed is not None:
            failed.extend(check_gated_run(package, paths, listed, verdicts))

    others = [package for package in packages if package not in grouped]
    if len(others) + len(grouped) != len(packages):
        raise GoError("the packages with and without entries do not add up")
    if others and run(["go", "test", "-count=1"] + others) != 0:
        failed.append("the packages without entries")

    if failed:
        emit("::error::test gate failed: " + "; ".join(failed))
        return 1
    emit(
        "test gate passed: %d packages, %d of them with skipped entries (%d entries)"
        % (len(packages), len(grouped), len(entries))
    )
    return 0


def verdict_alone(package, path):
    """Run one entry on its own and return its verdict, or None.

    An entry that starts and stops the test binary before it reports, for
    example by exiting the process, counts as failing.
    """
    status, verdicts, started = go_test_json(
        ["-count=1", "-run", exact_paths([path]), package]
    )
    if path in verdicts:
        return verdicts[path]
    if path in started and status != 0:
        return "fail"
    return None


def still_failing(entries, list_path):
    packages = module_packages()
    grouped = by_package(entries)
    listings = check_list(grouped, packages)

    stale = []
    failed = []
    for package, paths in grouped.items():
        if listings[package] is None:
            # The run of this package below reports the reason.
            failed.append("go test -list for " + package)
        emit("::group::Expected failures of the listed tests in " + package)
        _, verdicts, started = go_test_json(
            ["-count=1", "-run", exact_paths(paths), package]
        )
        found = {}
        if started:
            for path in paths:
                # No verdict can mean that an earlier listed test stopped the
                # test binary, so such an entry is asked again on its own.
                found[path] = verdicts.get(path) or verdict_alone(package, path)
        emit("::endgroup::")
        if not started:
            # For example a build failure. The output above has the reason.
            failed.append("no listed test of %s started" % package)
            continue
        for path in paths:
            if found[path] == "fail":
                emit("still fails: %s %s" % (package, path))
            elif found[path] == "pass":
                stale.append((package, path, "it passes"))
            elif found[path] == "skip":
                stale.append((package, path, "it skips itself"))
            else:
                stale.append((package, path, "it did not run"))

    for package, path, reason in stale:
        emit(
            "::error::listed test no longer fails on this host (%s): %s %s. "
            "Delete its line from %s, or correct the line."
            % (reason, package, path, list_path)
        )
    if failed:
        emit("::error::listed tests check failed: " + "; ".join(failed))
    if stale or failed:
        return 1
    emit("all %d listed tests still fail on this host" % len(entries))
    return 0


def main(arguments):
    if len(arguments) != 2 or arguments[0] not in MODES:
        raise ListError("usage: go_test_gate.py gate|still-failing LIST")
    entries = read_entries(arguments[1])
    if arguments[0] == "gate":
        return gate(entries)
    return still_failing(entries, arguments[1])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ListError as error:
        emit("::error::test gate list: %s" % error)
        sys.exit(2)
    except GoError as error:
        emit("::error::test gate: %s" % error)
        sys.exit(1)
