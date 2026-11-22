#!/usr/bin/env python3
"""CI test gate for this Go module.

Usage, from the module root:

    python3 -I -B .github/ci/go_test_gate.py gate LIST
    python3 -I -B .github/ci/go_test_gate.py environment-only LIST

LIST is a text file naming the tests that cannot pass on a CI runner for host
reasons. An entry is one line holding exactly a package import path, one
space and a top-level test name:

    execution-substrate/es/app TestExample

Empty lines and lines whose first character is "#" are ignored. Every other
line must be an entry. A test name may hold only ASCII letters, digits and
underscores, so an entry can never act as a regular expression. An entry
applies only to the package it names.

gate
    Checks the list, then runs every package of the module. A package with
    entries runs on its own with exactly its own entries skipped. All other
    packages run with nothing skipped. Exits 0 only if every run passes.

environment-only
    Runs only the listed tests, each in the package its entry names.

Exit status: 0 on success, 1 when a Go command fails, 2 when the list or the
command line is wrong. No test has run when the status is 2.
"""

import re
import shlex
import subprocess
import sys

# One entry: a package import path, one space, a top-level test name. The test
# name is letters, digits and underscores only, so it has no meaning as a
# regular expression beyond its own text. The package is accepted only if it
# is exactly one of the import paths that "go list ./..." prints, so it cannot
# be a package pattern either.
ENTRY = re.compile(r"([A-Za-z0-9_][A-Za-z0-9_./-]*) (Test[A-Za-z0-9_]+)")

MODES = ("gate", "environment-only")


class ListError(Exception):
    """The list or the command line is wrong. Exit status 2."""


class GoError(Exception):
    """A Go command that the gate depends on failed. Exit status 1."""


def read_entries(path):
    """Return the list's entries as (package, test name) pairs, in file order."""
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
                "%s line %d is not '<package> <TestName>': %r" % (path, number, line)
            )
        entry = (match.group(1), match.group(2))
        if entry in entries:
            raise ListError("%s line %d repeats an entry: %r" % (path, number, line))
        entries.append(entry)
    return entries


def by_package(entries):
    """Group test names under their package, keeping list order."""
    grouped = {}
    for package, name in entries:
        grouped.setdefault(package, []).append(name)
    return grouped


def exact_names(names):
    """Return a pattern that matches exactly the given top-level test names."""
    return "^(" + "|".join(names) + ")$"


def show(command):
    print("+ " + shlex.join(command), flush=True)


def run(command):
    """Run a command with its output going to the log. Return its exit status."""
    show(command)
    return subprocess.run(command).returncode


def capture(command):
    """Run a command and return its exit status and its standard output."""
    show(command)
    done = subprocess.run(command, stdout=subprocess.PIPE)
    return done.returncode, done.stdout.decode("utf-8", "replace")


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


def require_module_packages(grouped, packages):
    for package in grouped:
        if package not in packages:
            raise ListError("listed package is not a package of this module: %s" % package)


def undefined_tests(package, names):
    """Return the listed names that the package's test binary does not define.

    Returns None when the test binary could not be listed, for example because
    the package does not compile. Listing runs no test.
    """
    status, output = capture(["go", "test", "-list", exact_names(names), package])
    if status != 0:
        return None
    defined = set(output.split("\n"))
    return [name for name in names if name not in defined]


def gate(entries):
    packages = module_packages()
    grouped = by_package(entries)
    require_module_packages(grouped, packages)

    failed = []
    for package, names in grouped.items():
        undefined = undefined_tests(package, names)
        if undefined is None:
            # The run of this package below reports the reason.
            failed.append("go test -list for " + package)
        elif undefined:
            raise ListError(
                "listed test is not defined in package %s: %s"
                % (package, ", ".join(undefined))
            )

    for package, names in grouped.items():
        if run(["go", "test", "-count=1", "-skip", exact_names(names), package]) != 0:
            failed.append(package)

    others = [package for package in packages if package not in grouped]
    if len(others) + len(grouped) != len(packages):
        raise GoError("the packages with and without entries do not add up")
    if others and run(["go", "test", "-count=1"] + others) != 0:
        failed.append("the packages without entries")

    if failed:
        print("::error::test gate failed: " + "; ".join(failed), flush=True)
        return 1
    print(
        "test gate passed: %d packages, %d of them with skipped entries (%d entries)"
        % (len(packages), len(grouped), len(entries)),
        flush=True,
    )
    return 0


def environment_only(entries):
    packages = module_packages()
    grouped = by_package(entries)
    require_module_packages(grouped, packages)

    status = 0
    for package, names in grouped.items():
        if run(["go", "test", "-count=1", "-run", exact_names(names), package]) != 0:
            status = 1
    return status


def main(arguments):
    if len(arguments) != 2 or arguments[0] not in MODES:
        raise ListError("usage: go_test_gate.py gate|environment-only LIST")
    entries = read_entries(arguments[1])
    if arguments[0] == "gate":
        return gate(entries)
    return environment_only(entries)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ListError as error:
        print("::error::test gate list: %s" % error, flush=True)
        sys.exit(2)
    except GoError as error:
        print("::error::test gate: %s" % error, flush=True)
        sys.exit(1)
