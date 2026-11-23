#!/usr/bin/env python3
"""Run as root the tests of one package that skip themselves without root.

    python3 -I -B .github/ci/go_test_as_root.py LIST PACKAGE

LIST is the list that go_test_gate.py reads. PACKAGE is the import path of
one package of the module in the current directory.

Some tests need a privilege that the account of the CI job does not have.
The tests of the PID-namespace containment of the Remote Alpha TLS status
collector create PID namespaces, and that needs root on Linux. Such a test
asks the kernel by an attempt and skips itself on a refusal. LIST therefore
names it with "skips-itself", and the step "Test" holds it to that. A test
that skipped itself has proved nothing. This step runs those tests where
they can pass.

What it does:

1. It takes every "skips-itself" line of LIST for PACKAGE. There has to be
   at least one, and each has to name a top-level test.
2. It builds the test binary of PACKAGE as the current user, in a new
   directory that only this user can write.
3. It asks that binary which of the listed tests it holds, and requires all
   of them.
4. It runs the binary once through "sudo -n" with an emptied environment, in
   the directory of the package, for exactly the listed tests.
5. It fails unless the binary ends with status 0 and reports exactly one
   verdict for every listed test, a pass, and no verdict for any other
   top-level test. A test that skips itself as root fails this step.

Only number 4 runs as root, and it runs only the test binary. Nothing else in
the CI job uses sudo. The go command never runs as root.

So a line "skips-itself PACKAGE TestName" for this package says two things:
the test skips itself in the step "Test", and it passes as root here. While
the workflow names PACKAGE for this step, a test of PACKAGE that skips itself
for any other reason cannot be listed: it fails here, in the change that
adds it.

Exit status: 0 when every listed test passed as root, 1 when one did not or
a command failed, 2 when LIST or the arguments are wrong.
"""

import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "go_test_gate.py")
# The whole of what runs as root is this prefix and the test binary with its
# flags. "env -i" empties the environment; sudo would keep parts of it.
ELEVATE = ("sudo", "-n", "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin")
TIME_LIMIT = "10m"
TOP_LEVEL = re.compile(r"Test[A-Za-z0-9_]*")
# A verdict line of a top-level test starts in the first column. go test
# indents the verdict lines of subtests and everything a test logs.
VERDICT = re.compile(r"--- (PASS|FAIL|SKIP): (\S+) \(\d+\.\d+s\)")


class ListError(Exception):
    pass


class StepError(Exception):
    pass


def emit(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def load_gate():
    spec = importlib.util.spec_from_file_location("go_test_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def listed(list_path, package):
    """Return the tests of package that LIST says skip themselves, in file order."""
    gate = load_gate()
    try:
        _entries, skips = gate.read_entries(list_path)
    except gate.ListError as error:
        raise ListError(str(error))
    names = [path for owner, path in skips if owner == package]
    if not names:
        raise ListError(
            "%s has no '%s %s <TestName>' line, so this step would run nothing"
            % (list_path, gate.SELF_SKIP, package)
        )
    for name in names:
        if TOP_LEVEL.fullmatch(name) is None:
            raise ListError(
                "%s: '%s %s %s' does not name a top-level test; this step runs "
                "whole tests only" % (list_path, gate.SELF_SKIP, package, name)
            )
    return names


def judge(names, status, output):
    """Return what is wrong with one run of the listed tests; empty when nothing is."""
    verdicts = {}
    for line in output.split("\n"):
        match = VERDICT.fullmatch(line)
        if match is not None:
            verdicts.setdefault(match.group(2), []).append(match.group(1))
    problems = []
    for name in names:
        seen = verdicts.get(name, [])
        if not seen:
            problems.append("%s reported no verdict" % name)
        elif seen != ["PASS"]:
            problems.append("%s did not pass as root: %s" % (name, ", ".join(seen)))
    for name in sorted(verdicts):
        if name not in names:
            problems.append("%s ran although the list does not name it" % name)
    if status != 0:
        problems.append("the test binary ended with status %d" % status)
    return problems


def capture(command, directory=None):
    emit("+ " + " ".join(command))
    try:
        completed = subprocess.run(
            command, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        raise StepError("cannot run %s: %s" % (command[0], error.strerror))
    return completed.returncode, completed.stdout.decode("utf-8", "replace")


def checked(command, directory=None):
    status, output = capture(command, directory)
    if status != 0:
        emit(output.rstrip("\n"))
        raise StepError("%s ended with status %d" % (" ".join(command), status))
    return output


def main(arguments):
    if len(arguments) != 2:
        raise ListError("usage: go_test_as_root.py LIST PACKAGE")
    list_path, package = arguments
    names = listed(list_path, package)
    directory = checked(["go", "list", "-f", "{{.Dir}}", package]).strip()
    if not os.path.isdir(directory):
        raise StepError("go list named no directory for %s" % package)
    pattern = "^(%s)$" % "|".join(names)
    with tempfile.TemporaryDirectory() as scratch:
        binary = os.path.join(scratch, "package.test")
        checked(["go", "test", "-c", "-o", binary, package])
        if not os.path.isfile(binary):
            raise StepError("%s has no test binary" % package)
        present = checked([binary, "-test.list", pattern], directory).split()
        missing = [name for name in names if name not in present]
        if missing:
            raise StepError(
                "the list names tests that %s does not have: %s" % (package, ", ".join(missing))
            )
        status, output = capture(
            list(ELEVATE)
            + [binary, "-test.run", pattern, "-test.v", "-test.count=1", "-test.timeout=" + TIME_LIMIT],
            directory,
        )
    emit(output.rstrip("\n"))
    problems = judge(names, status, output)
    for problem in problems:
        emit("::error::tests as root: %s" % problem)
    if problems:
        return 1
    emit("tests as root passed: %d of %s" % (len(names), package))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ListError as error:
        emit("::error::tests as root, list: %s" % error)
        sys.exit(2)
    except StepError as error:
        emit("::error::tests as root: %s" % error)
        sys.exit(1)
