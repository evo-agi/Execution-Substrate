package app_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The take-back program's bounds on what it reads and copies (re-check 52 of
// #83: Opus's A52-1, and the three guards Sonnet's S52-1 found unpinned).

// takeBackFolders makes a config folder with its tls folder and a data
// folder under a new temporary folder.
func takeBackFolders(t *testing.T) (config, data string) {
	t.Helper()
	root := t.TempDir()
	config, data = filepath.Join(root, "etc"), filepath.Join(root, "data")
	for _, folder := range []string{filepath.Join(config, "tls"), data} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// As the program leaves it, so that it says nothing of the folder.
	if err := os.Chmod(data, 0o700); err != nil {
		t.Fatal(err)
	}
	return config, data
}

// writeOpenFile writes content to path, mode 0666 whatever the umask, so
// that the program takes it back.
func writeOpenFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
}

// runTakeBackWrapped runs the program under a Python wrapper that changes
// the os module first, as the test user, with a time limit.
func runTakeBackWrapped(t *testing.T, program, wrapper string, env []string, limit time.Duration, config, data string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-I", "-c", wrapper, program, config, data)
	command.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("the program (ended after %v at most): %v\n%s\n%s", limit, err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

// A52-1: one run copies at most 4 MiB in all. Many sparse files cost the
// account nothing; each copy cost root its whole size, 50 MiB for 50 of
// them in one real dpkg run. Past the budget a file is set aside, which is a
// rename and costs nothing.
func TestNomadTakeBackProgramCopiesAtMostFourMiBInOneRun(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, data := takeBackFolders(t)
	var names []string
	for i := 0; i < 6; i++ {
		path := filepath.Join(config, fmt.Sprintf("%c.json", 'a'+i))
		writeOpenFile(t, path, "")
		if err := os.Truncate(path, 1<<20); err != nil {
			t.Fatal(err)
		}
		names = append(names, path)
	}
	stdout, stderr, err := runTakeBack(t, program, false, config, data)
	if err != nil {
		t.Fatalf("the program: %v\n%s\n%s", err, stdout, stderr)
	}
	var took []string
	for _, path := range names[:4] {
		took = append(took, regexp.QuoteMeta(tookBackLine(path, fmt.Sprintf("uid %d, gid %d, 0666", os.Getuid(), os.Getgid()))))
	}
	requireLines(t, stdout, took)
	requireLines(t, stderr, []string{
		setAsideLine(names[4], "1048576 bytes, more than the 0 left of the 4194304 this run copies in all", config, ""),
		setAsideLine(names[5], "1048576 bytes, more than the 0 left of the 4194304 this run copies in all", config, ""),
		lookLine(config)})
	for _, path := range names[:4] {
		info, err := os.Lstat(path)
		if err != nil || info.Size() != 1<<20 || info.Mode().Perm() != 0o644 {
			t.Fatalf("%s after the run: %v %v", path, info, err)
		}
	}
	for _, path := range names[4:] {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s is still where Nomad reads it: %v", path, err)
		}
	}
}

// A52-1, the same bound once read: a file that looked small enough for what
// is left of the budget, but holds more when read, is set aside.
func TestNomadTakeBackProgramStopsAtTheBudgetOnceRead(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, data := takeBackFolders(t)
	for i, size := range []int64{1 << 20, 1 << 20, 1 << 20, 1<<20 - 10} {
		path := filepath.Join(config, fmt.Sprintf("%c.json", 'a'+i))
		writeOpenFile(t, path, "")
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
	}
	grows := filepath.Join(config, "e.json")
	writeOpenFile(t, grows, "x\n")
	wrapper := `
import os, runpy, sys
target = os.environ["GROWS"]
real_open, real_read = os.open, os.read
grown = set()
def tracking_open(path, flags, *args, **kwargs):
    fd = real_open(path, flags, *args, **kwargs)
    if path == target:
        grown.add(fd)
    return fd
def growing_read(fd, n):
    return b"#" * n if fd in grown else real_read(fd, n)
os.open, os.read = tracking_open, growing_read
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`
	_, stderr := runTakeBackWrapped(t, program, wrapper, []string{"GROWS=" + grows}, 30*time.Second, config, data)
	requireLines(t, stderr, []string{
		setAsideLine(grows, "more than the 10 bytes left of the 4194304 this run copies in all, once read", config, ""),
		lookLine(config)})
}

// Sonnet's P16: the read loop stops at the bound. A file another account
// keeps appending to looks small to lstat and then does not end; with
// os.read made to return data without end, and the address space capped,
// the program stops at 1 MiB and sets the file aside, where an unbounded
// loop ends in a MemoryError.
func TestNomadTakeBackProgramStopsReadingAFileThatDoesNotEnd(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, data := takeBackFolders(t)
	path := filepath.Join(config, "extra.hcl")
	writeOpenFile(t, path, "x\n")
	wrapper := `
import os, resource, runpy, sys
resource.setrlimit(resource.RLIMIT_AS, (1 << 29, 1 << 29))
def endless(fd, n):
    return b"#" * n
os.read = endless
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`
	_, stderr := runTakeBackWrapped(t, program, wrapper, nil, 30*time.Second, config, data)
	requireLines(t, stderr, []string{
		setAsideLine(path, "more than the 1048576 bytes a file Nomad reads may hold, once read", config, ""),
		lookLine(config)})
}

// Sonnet's P36: the file is opened without blocking. An entry swapped for a
// FIFO between the program's lstat and its open must not make the program
// wait for a writer that never comes: one planted FIFO would hang every dpkg
// run. The device and inode check after the open then refuses it.
func TestNomadTakeBackProgramDoesNotWaitOnAFifoSwappedInBeforeTheOpen(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, data := takeBackFolders(t)
	path := filepath.Join(config, "extra.hcl")
	writeOpenFile(t, path, "x\n")
	wrapper := `
import os, runpy, sys
target = os.environ["CHANGED"]
real_open = os.open
done = []
def changing_open(path, flags, *args, **kwargs):
    if path == target and not done:
        done.append(path)
        os.rename(path, path + ".old")
        os.mkfifo(path)
    return real_open(path, flags, *args, **kwargs)
os.open = changing_open
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`
	_, stderr := runTakeBackWrapped(t, program, wrapper, []string{"CHANGED=" + path}, 20*time.Second, config, data)
	requireLines(t, stderr, []string{setAsideLine(path, "it changed while it was taken back", config, ""), lookLine(config)})
}

// Sonnet's P25: the set-aside folder is named from the folder as given, less
// a trailing slash. The setup and dpkg give none, but an operator running
// the program by hand may, and the setup's stop and the box check look only
// beside the folder: a set-aside folder made inside it would be where Nomad
// reads.
func TestNomadTakeBackProgramSetsAsideBesideAFolderGivenWithATrailingSlash(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, data := takeBackFolders(t)
	link := filepath.Join(config, "extra.hcl")
	if err := os.Symlink("/etc/hostname", link); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runTakeBack(t, program, false, config+"/", data+"/")
	if err != nil {
		t.Fatalf("the program: %v\n%s\n%s", err, stdout, stderr)
	}
	if _, err := os.Lstat(setAsideFolder(config)); err != nil {
		t.Fatalf("nothing is set aside beside %s: %v\n%s", config, err, stderr)
	}
	if _, err := os.Lstat(filepath.Join(config, ".execution-substrate-set-aside")); !os.IsNotExist(err) {
		t.Fatalf("a set-aside folder was made inside %s: %v", config, err)
	}
}
