package executionsubstrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The collector's cleanup reaches the target's process table through three
// functions. A fixture script either leaves all of them real, replaces all of
// them, or replaces the operating-system primitives of each one that it
// leaves real. These tests hold that rule, which
// .docs/system_overview/capability_probing.md states, for every fixture
// script of this package, and they hold the shared local boundary by
// behavior.
//
// The guard reads the text of the scripts. It refuses a script that replaces
// part of the boundary, that sets the capability flag without the real
// probe, that replaces the probe and then runs an entry point of the
// collector with a path to the fixed command left real, or that calls the
// cleanup directly without the real probe or the live prelude. The entry
// points run the probe and then set the flag themselves, so a stand-in for
// the probe followed by an entry point is the flag set by hand.
//
// It judges one script as a whole and does not follow its control flow, and
// it knows the ways of replacing that this package uses: an assignment,
// setattr with a literal name, mock.patch.object, and a namespace entry.
// Whatever is assigned counts as a stand-in: the guard does not see that a
// script assigns the real function back, or assigns on another object. The
// behavior tests below do not depend on it.

type remoteAlphaESStatusFixtureScript struct {
	file string
	line int
	text string
}

func (s remoteAlphaESStatusFixtureScript) String() string {
	return fmt.Sprintf("%s:%d", s.file, s.line)
}

// remoteAlphaESStatusFixtureScripts returns every string expression in the
// test files of this package: one string literal, or one "+" chain of string
// literals and package-level string constants, with the constants resolved.
// A local constant is one such expression where it is declared. A chain with
// an operand that cannot be resolved is returned in unresolved with the text
// of its resolvable parts, so that the caller can refuse it.
func remoteAlphaESStatusFixtureScripts(t *testing.T) (scripts, unresolved []remoteAlphaESStatusFixtureScript) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(executionSubstrateRepoRoot, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	// Package-level constants and variables by name. A name that is declared
	// more than once in a block of several values is not resolved.
	declared := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				if len(value.Names) == len(value.Values) {
					for i, name := range value.Names {
						declared[name.Name] = value.Values[i]
					}
				}
			}
		}
	}
	resolving := map[string]bool{}
	var eval func(expr ast.Expr) (string, bool, bool)
	// eval returns the text, whether the expression holds a string literal,
	// and whether every operand was resolved.
	eval = func(expr ast.Expr) (string, bool, bool) {
		switch e := expr.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false, false
			}
			text, err := strconv.Unquote(e.Value)
			if err != nil {
				t.Fatalf("%s: %v", fset.Position(e.Pos()), err)
			}
			return text, true, true
		case *ast.ParenExpr:
			return eval(e.X)
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false, false
			}
			left, leftLiteral, leftResolved := eval(e.X)
			right, rightLiteral, rightResolved := eval(e.Y)
			return left + right, leftLiteral || rightLiteral, leftResolved && rightResolved
		case *ast.Ident:
			value, ok := declared[e.Name]
			if !ok || resolving[e.Name] {
				return "", false, false
			}
			resolving[e.Name] = true
			text, literal, resolved := eval(value)
			delete(resolving, e.Name)
			if !literal || !resolved {
				return "", false, false
			}
			// A resolved constant counts as text, not as a literal of its
			// own, so that a bare reference is no expression by itself.
			return text, false, true
		}
		return "", false, false
	}
	for i, file := range files {
		name := filepath.Base(names[i])
		ast.Inspect(file, func(node ast.Node) bool {
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			switch expr.(type) {
			case *ast.BasicLit, *ast.BinaryExpr, *ast.ParenExpr:
			default:
				return true
			}
			text, literal, resolved := eval(expr)
			if !literal {
				return true
			}
			script := remoteAlphaESStatusFixtureScript{file: name, line: fset.Position(expr.Pos()).Line, text: text}
			if resolved {
				scripts = append(scripts, script)
			} else {
				unresolved = append(unresolved, script)
			}
			// The whole chain is one script; its parts are not judged again.
			return false
		})
	}
	if len(files) == 0 || len(scripts) == 0 {
		t.Fatalf("no test files or no string expressions found in %s", executionSubstrateRepoRoot)
	}
	return scripts, unresolved
}

// The ways in which a fixture script replaces something of the loaded
// collector: an attribute assignment, setattr with a literal name,
// mock.patch.object, or an entry of a namespace that the script executes the
// collector in.
func remoteAlphaESStatusReplaces(text, owner, name string) bool {
	var patterns []string
	if owner == "" {
		// Something of the collector itself: module.name=, setattr(module,
		// "name", patch.object(module, "name", or namespace["name"]=.
		patterns = []string{
			`\b\w+\.` + name + `\s*=[^=]`,
			`(?:setattr|patch\.object)\(\s*\w+\s*,\s*["']` + name + `["']`,
			`\[["']` + name + `["']\]\s*=[^=]`,
		}
	} else {
		// A primitive of a standard module, reached through the collector
		// (module.os.name) or directly (os.name): both are the same object.
		patterns = []string{
			`(?:\b\w+\.)?\b` + owner + `\.` + name + `\s*=[^=]`,
			`(?:setattr|patch\.object)\(\s*(?:\w+\.)?` + owner + `\s*,\s*["']` + name + `["']`,
		}
	}
	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(text) {
			return true
		}
	}
	return false
}

type remoteAlphaESStatusBoundaryUse struct {
	scan, signal, identity          bool   // the three functions, replaced as functions
	pidfd                           bool   // a pidfd primitive replaced by itself
	scanCut, signalCut, identityCut bool   // replaced as functions or below them
	ready                           bool   // the capability flag set by the script
	probed                          bool   // the real capability probe is run
	live                            bool   // the live prelude decides by attempt
	reach                           bool   // the cleanup owner or hold is called directly
	probeStandIn                    bool   // the probe or its backend is replaced
	entryOpen                       string // an entry point that the script names, with a real path to the fixed command
}

func (use remoteAlphaESStatusBoundaryUse) whole() bool {
	return use.scanCut && use.signalCut && use.identityCut
}

func remoteAlphaESStatusBoundaryUseOf(text string) remoteAlphaESStatusBoundaryUse {
	var use remoteAlphaESStatusBoundaryUse
	use.scan = remoteAlphaESStatusReplaces(text, "", "scan_group_members")
	use.signal = remoteAlphaESStatusReplaces(text, "", "signal_same_group_members")
	use.identity = remoteAlphaESStatusReplaces(text, "", "read_proc_identity")
	// A primitive is replaced by itself, or the collector's whole os or
	// signal module is replaced by an object of the script. Such an object
	// may pass every other name on to the real module, so it stands in only
	// for the primitives that the script defines.
	primitive := func(owner, name string) bool {
		if remoteAlphaESStatusReplaces(text, owner, name) {
			return true
		}
		defined := regexp.MustCompile(`\bdef\s+` + name + `\s*\(|\b` + name + `\s*=[^=]`).MatchString(text)
		return defined && remoteAlphaESStatusReplaces(text, "", owner)
	}
	listdir := primitive("os", "listdir")
	osOpen := primitive("os", "open")
	pidfdOpen := primitive("os", "pidfd_open")
	pidfdSend := primitive("signal", "pidfd_send_signal")
	// scan_group_members lists /proc. signal_same_group_members opens a pidfd
	// and signals through it. read_proc_identity opens /proc/<pid>/stat and
	// asks pidfd_open whether the process is absent.
	use.scanCut = use.scan || listdir
	use.signalCut = use.signal || (pidfdOpen && pidfdSend)
	use.identityCut = use.identity || (osOpen && pidfdOpen)
	use.pidfd = remoteAlphaESStatusReplaces(text, "os", "pidfd_open") || remoteAlphaESStatusReplaces(text, "signal", "pidfd_send_signal")
	use.ready = regexp.MustCompile(`PROCESS_CAPABILITY_READY(?:["']\])?\s*=\s*True|(?:setattr|patch\.object)\(\s*\w+\s*,\s*["']PROCESS_CAPABILITY_READY["']\s*,\s*True`).MatchString(text)
	replaced := func(name string) bool {
		return remoteAlphaESStatusReplaces(text, "", name)
	}
	// The probe is a stand-in when the script replaces it, or the backend
	// class from which the real probe takes its operations.
	use.probeStandIn = replaced("validate_process_capability") || replaced("ProcessCapabilityBackend")
	use.probed = regexp.MustCompile(`\.validate_process_capability\(\)`).MatchString(text) && !use.probeStandIn
	use.live = strings.Contains(text, remoteAlphaESProcessIdentityLivePrelude)
	// The two entry points run the probe and then set the capability flag
	// themselves. From there the fixed command, the only caller of the
	// cleanup, is reached along the paths below, which
	// TestRemoteAlphaESServiceTLSStatusLocalBoundaryKnowsTheCallGraph holds
	// against the collector's source. An entry point counts as used when the
	// script names it as something of the collector, called or not.
	named := func(name string) bool {
		return regexp.MustCompile(`(?:\.|\[["']|,\s*["'])` + name + `\b`).MatchString(text)
	}
	checks := replaced("cert_role") && replaced("key_pair") && replaced("verify_chain")
	for _, entry := range []struct{ name, below string }{
		{"main", "collect"}, {"diagnostic_main", "diagnose_first_rejection"},
	} {
		if named(entry.name) && !replaced("run_fixed") && !replaced(entry.below) && !checks && use.entryOpen == "" {
			use.entryOpen = entry.name
		}
	}
	// The cleanup called directly, without run_fixed and its capability
	// check. own_child_until_proved goes to terminate_child for a child that
	// is not reaped and to prove_group_absent for a reaped one.
	calls := func(name string) bool {
		return regexp.MustCompile(`\.` + name + `\(`).MatchString(text)
	}
	reapedChild := regexp.MustCompile(`_status_reaped\s*=\s*True`).MatchString(text)
	owner := calls("own_child_until_proved") && !replaced("own_child_until_proved") &&
		(!replaced("terminate_child") || (reapedChild && !replaced("prove_group_absent")))
	use.reach = owner ||
		(calls("terminate_child") && !replaced("terminate_child")) ||
		(calls("prove_group_absent") && !replaced("prove_group_absent"))
	return use
}

// remoteAlphaESStatusBoundaryFault says what is wrong with one fixture
// script, or "" when the script keeps the rule. It judges the text of a
// script as a whole. It does not follow the script's control flow.
func remoteAlphaESStatusBoundaryFault(text string) string {
	use := remoteAlphaESStatusBoundaryUseOf(text)
	missing := func() string {
		var names []string
		if !use.scanCut {
			names = append(names, "scan_group_members")
		}
		if !use.signalCut {
			names = append(names, "signal_same_group_members")
		}
		if !use.identityCut {
			names = append(names, "read_proc_identity")
		}
		return strings.Join(names, ", ")
	}
	if use.whole() {
		return ""
	}
	if use.scan || use.signal || use.identity || use.pidfd {
		return "replaces part of the process boundary and leaves real, with real operating-system primitives: " + missing()
	}
	if use.ready && !use.probed {
		return "declares the process capability proved without the real probe and leaves real: " + missing()
	}
	if use.probeStandIn && use.entryOpen != "" {
		return "replaces the capability probe and runs " + use.entryOpen + ", which then declares the capability itself, " +
			"with a path to the fixed command left real and with real: " + missing()
	}
	if use.reach && !use.probed && !use.live {
		return "calls the cleanup owner or hold without the real probe or the live prelude and leaves real: " + missing()
	}
	return ""
}

// The guard judges a script that holds one of these names: the three
// functions of the boundary, the capability flag, the probe and its backend
// class, the two pidfd primitives, the cleanup owner with the two functions
// below it, and the PID namespace of a fixed command with the namespace part
// of the probe. remoteAlphaESStatusBoundaryNamePins holds one refused
// script for each name, so that a name cannot leave this list unnoticed.
var remoteAlphaESStatusBoundaryNames = []string{
	"scan_group_members", "signal_same_group_members", "read_proc_identity",
	"PROCESS_CAPABILITY_READY", "validate_process_capability", "ProcessCapabilityBackend",
	"pidfd_open", "pidfd_send_signal",
	"own_child_until_proved", "terminate_child", "prove_group_absent",
	"ChildNamespace", "validate_child_namespace",
}

var remoteAlphaESStatusNamesBoundary = regexp.MustCompile(strings.Join(remoteAlphaESStatusBoundaryNames, "|"))

// remoteAlphaESStatusGuardVerdict is the guard's judgement of one script, as
// the scan of the package applies it: a script that holds none of the names
// is not judged at all.
func remoteAlphaESStatusGuardVerdict(text string) (judged bool, fault string) {
	if !remoteAlphaESStatusNamesBoundary.MatchString(text) {
		return false, ""
	}
	if fault := remoteAlphaESStatusBoundaryFault(text); fault != "" {
		return true, fault
	}
	// The namespace rule reads only a script that names the namespace pair.
	if strings.Contains(text, "ChildNamespace") || strings.Contains(text, "validate_child_namespace") {
		return true, remoteAlphaESStatusNamespaceFault(text)
	}
	return true, ""
}

// The samples of the guard's own tests spell the names of the list in
// capitals, so that the scan of the package does not take a sample for a
// fixture. This puts the real names in.
var remoteAlphaESStatusSampleNames = strings.NewReplacer("SCAN", "scan_group_members", "SIGNAL", "signal_same_group_members",
	"IDENTITY", "read_proc_identity", "PROBE", "validate_process_capability", "READY", "PROCESS_CAPABILITY_READY",
	"BACKEND", "ProcessCapabilityBackend", "PIDFD_OPEN", "pidfd_open", "PIDFD_SEND", "pidfd_send_signal",
	"OWNER", "own_child_until_proved", "TERMINATE", "terminate_child", "HOLD", "prove_group_absent",
	"CHILD_NS", "ChildNamespace", "NS_PROBE", "validate_child_namespace")

// One script for each name of the list. Each holds that name and no other
// name of the list, and the guard refuses each. So a name that is taken out
// of the list fails TestRemoteAlphaESServiceTLSStatusLocalBoundaryPinsItsNames:
// its script is then no longer judged.
var remoteAlphaESStatusBoundaryNamePins = map[string]string{
	"scan_group_members":          "module.SCAN=lambda pgid: []\n",
	"signal_same_group_members":   "m.SIGNAL=lambda pgid,signum: None\n",
	"read_proc_identity":          "m.IDENTITY=lambda pid: None\n",
	"PROCESS_CAPABILITY_READY":    "module.READY=True\n",
	"validate_process_capability": "module.PROBE=lambda: None\nstatus=module.main([])\n",
	"ProcessCapabilityBackend":    "module.BACKEND=FakeBackend\nstatus=module.main([])\n",
	"pidfd_open":                  "m.os.PIDFD_OPEN=lambda pid,flags: 9\n",
	"pidfd_send_signal":           `mock.patch.object(signal, "PIDFD_SEND", side_effect=s, create=True)` + "\n",
	"own_child_until_proved":      "m.OWNER(proc)\n",
	"terminate_child":             "m.TERMINATE(proc)\n",
	"prove_group_absent":          "seen=module.HOLD(pgid)\n",
	"ChildNamespace":              "module.CHILD_NS=type(\"x\",(),{})\n",
	"validate_child_namespace":    "module.NS_PROBE=lambda: None\n",
}

func TestRemoteAlphaESServiceTLSStatusLocalBoundaryPinsItsNames(t *testing.T) {
	if len(remoteAlphaESStatusBoundaryNamePins) != len(remoteAlphaESStatusBoundaryNames) {
		t.Errorf("%d names are pinned and the guard looks for %d", len(remoteAlphaESStatusBoundaryNamePins), len(remoteAlphaESStatusBoundaryNames))
	}
	for _, name := range remoteAlphaESStatusBoundaryNames {
		sample, ok := remoteAlphaESStatusBoundaryNamePins[name]
		if !ok {
			t.Errorf("the guard looks for %s and no script pins it", name)
			continue
		}
		text := remoteAlphaESStatusSampleNames.Replace(sample)
		if held := remoteAlphaESStatusNamesBoundary.FindAllString(text, -1); len(held) != 1 || held[0] != name {
			t.Errorf("the script that pins %s holds %q", name, held)
		}
		if judged, fault := remoteAlphaESStatusGuardVerdict(text); !judged || fault == "" {
			t.Errorf("the script that pins %s: judged=%v, fault %q; want it judged and refused", name, judged, fault)
		}
	}
	for name := range remoteAlphaESStatusBoundaryNamePins {
		if !remoteAlphaESStatusNamesBoundary.MatchString(name) {
			t.Errorf("%s is pinned and the guard does not look for it", name)
		}
	}
}

// The PID namespace of a fixed command and the namespace part of the
// capability probe are replaced together or not at all. A fixture with only
// one of them replaced is neither a local fixture nor a test of the
// containment.
func remoteAlphaESStatusNamespaceFault(text string) string {
	namespace := remoteAlphaESStatusReplaces(text, "", "ChildNamespace")
	probe := remoteAlphaESStatusReplaces(text, "", "validate_child_namespace")
	switch {
	case namespace && !probe:
		return "replaces the PID namespace of the fixed command and leaves the namespace part of the capability probe real"
	case probe && !namespace:
		return "replaces the namespace part of the capability probe and leaves the PID namespace of the fixed command real"
	}
	return ""
}

func TestRemoteAlphaESServiceTLSStatusLocalBoundaryIsInjectedWhole(t *testing.T) {
	scripts, unresolved := remoteAlphaESStatusFixtureScripts(t)
	for _, script := range unresolved {
		if remoteAlphaESStatusNamesBoundary.MatchString(script.text) {
			t.Errorf("%s: a fixture script that names the process boundary is joined from a part that this guard cannot resolve", script)
		}
	}
	shared, judged, whole, probeStandIns, probeStandInsWhole, namespaceStandIns := 0, 0, 0, 0, 0, 0
	for _, script := range scripts {
		if strings.Contains(script.text, remoteAlphaESStatusLocalChildNamespace) && script.text != remoteAlphaESStatusLocalChildNamespace {
			namespaceStandIns++
		}
		seen, fault := remoteAlphaESStatusGuardVerdict(script.text)
		if !seen {
			continue
		}
		judged++
		if strings.Contains(script.text, remoteAlphaESStatusLocalProcessBoundary) && script.text != remoteAlphaESStatusLocalProcessBoundary {
			shared++
		}
		use := remoteAlphaESStatusBoundaryUseOf(script.text)
		if use.whole() {
			whole++
			t.Logf("%s: whole boundary replaced (functions: scan=%v signal=%v identity=%v; shared constant=%v)",
				script, use.scan, use.signal, use.identity, strings.Contains(script.text, remoteAlphaESStatusLocalProcessBoundary))
		} else if use.ready || use.reach {
			t.Logf("%s: boundary left real (real probe run=%v, live prelude=%v)", script, use.probed, use.live)
		}
		if use.probeStandIn && use.whole() {
			probeStandInsWhole++
		}
		if use.probeStandIn && !use.whole() {
			probeStandIns++
			t.Logf("%s: probe replaced, boundary not whole (flag set by the script=%v, entry point with a real path=%q)", script, use.ready, use.entryOpen)
		}
		if fault != "" {
			t.Errorf("%s: fixture script %s", script, fault)
		}
	}
	t.Logf("%d scripts name the process boundary or the namespace pair, %d use the shared local boundary, %d replace the whole boundary, %d replace the probe (%d with the whole boundary, %d without), %d use the shared namespace stand-in",
		judged, shared, whole, probeStandIns+probeStandInsWhole, probeStandInsWhole, probeStandIns, namespaceStandIns)
	// The guard must have seen the fixtures. The numbers are floors, so that
	// a new fixture does not have to change them, and a guard that no longer
	// sees the fixtures fails. A floor goes down only together with a fixture
	// that is removed.
	if shared < 22 || whole < 30 || probeStandIns < remoteAlphaESStatusProbeStandInFloor {
		t.Errorf("guard saw %d scripts with the shared local boundary, %d with the whole boundary replaced and %d with the probe replaced without it; want at least 22, 30 and %d",
			shared, whole, probeStandIns, remoteAlphaESStatusProbeStandInFloor)
	}

	// The rule itself, on the shapes that it must refuse and accept, judged
	// as the scan above judges a script.
	names := remoteAlphaESStatusSampleNames
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"nothing replaced", "module.OPENSSL=str(child)\nmodule.run_fixed((str(child),))\n", false},
		{"real probe then ready", "module.PROBE()\nmodule.READY=True\n", false},
		{"scan and signal without identity", "module.PROBE=lambda: None\nmodule.READY=True\n" +
			"module.SCAN=lambda pgid: [(pgid,0)]\nmodule.SIGNAL=lambda pgid,signum: os.kill(pgid,signum)\n", true},
		{"all three", "module.PROBE=lambda: None\nmodule.READY=True\n" +
			"module.SCAN=lambda pgid: [(pgid,0)]\nmodule.SIGNAL=lambda pgid,signum: os.kill(pgid,signum)\nmodule.IDENTITY=lambda pid: None\n", false},
		{"scan alone", "module.SCAN=lambda pgid: []\n", true},
		{"signal alone", "m.SIGNAL=lambda pgid,signum: None\n", true},
		{"identity alone", "m.IDENTITY=lambda pid: None\n", true},
		{"scan and identity without signal", "m.SCAN=scan\nm.IDENTITY=lambda pid:(1,1)\n", true},
		{"scan and identity after the real probe", "m.PROBE()\nm.READY=True\nm.SCAN=scan\nm.IDENTITY=lambda pid:(1,1)\n", true},
		{"scan and identity over fake modules", "class FakeOS:\n def PIDFD_OPEN(self,pid,flags):return 7\nm.os=FakeOS()\n" +
			"m.signal=types.SimpleNamespace(PIDFD_SEND=send)\nm.SCAN=scan\nm.IDENTITY=lambda pid:(1,1)\n", false},
		{"scan and identity over a fake os that passes the pidfd on", "class FakeOS:\n def close(self,fd):pass\nm.os=FakeOS()\n" +
			"m.signal=types.SimpleNamespace(PIDFD_SEND=send)\nm.SCAN=scan\nm.IDENTITY=lambda pid:(1,1)\n", true},
		{"scan and identity over a fake os only", "class FakeOS:\n def PIDFD_OPEN(self,pid,flags):return 7\nm.os=FakeOS()\nm.SCAN=scan\nm.IDENTITY=lambda pid:(1,1)\n", true},
		{"identity over replaced primitives", "module.IDENTITY=collector_identity\nmodule.os.listdir=listdir\nmodule.os.PIDFD_OPEN=opened;module.signal.PIDFD_SEND=sent\n", false},
		{"identity over a replaced listing only", "module.IDENTITY=collector_identity\nmodule.os.listdir=listdir\n", true},
		{"identity over a replaced listing and pidfd open only", "module.IDENTITY=collector_identity\nmodule.os.listdir=listdir\nmodule.os.PIDFD_OPEN=opened\n", true},
		{"scan over replaced primitives", "m.SCAN=scan\nm.os.open=opened\nos.PIDFD_OPEN=pidfd\nsignal.PIDFD_SEND=send\n", false},
		{"scan over replaced pidfd primitives only", "m.SCAN=scan\nos.PIDFD_OPEN=pidfd\nsignal.PIDFD_SEND=send\n", true},
		{"patched with mock", `with mock.patch.object(m,"SCAN",side_effect=members), mock.patch.object(m,"IDENTITY",x), mock.patch.object(m,"SIGNAL",y):pass` + "\n", false},
		{"patched with mock, one missing", `with mock.patch.object(m,"SCAN",side_effect=members), mock.patch.object(m,"IDENTITY",x):pass` + "\n", true},
		{"patched with mock over patched primitives", `mock.patch.object(m,"SCAN",members);mock.patch.object(m,"IDENTITY",x)` + "\n" +
			`mock.patch.object(os, "PIDFD_OPEN", side_effect=o, create=True);mock.patch.object(signal, "PIDFD_SEND", side_effect=s, create=True)` + "\n", false},
		{"namespace entries", `namespace["SCAN"] = members` + "\n" + `namespace["SIGNAL"] = s` + "\n" + `namespace["IDENTITY"] = i` + "\n", false},
		{"namespace entries, one missing", `namespace["SCAN"] = members` + "\n" + `namespace["IDENTITY"] = i` + "\n", true},
		{"ready by hand", "module.READY=True\n", true},
		{"ready after a replaced probe", "module.PROBE=lambda: None\nmodule.READY = True\n", true},
		{"ready after a replaced probe that is then called", "module.PROBE=lambda: None\nmodule.PROBE()\nmodule.READY = True\n", true},
		{"ready as a namespace entry", `namespace["READY"] = True` + "\n", true},
		{"ready patched with mock", `with mock.patch.object(m,"READY",True):pass` + "\n", true},
		{"ready compared", "assert m.READY is False\nok=m.READY==True\n", false},
		{"a pidfd primitive alone", "m.os.PIDFD_OPEN=lambda pid,flags: 9\n", true},
		{"a pidfd primitive patched alone", `mock.patch.object(signal, "PIDFD_SEND", side_effect=s, create=True)` + "\n", true},
		{"hold called with the boundary real", "seen=module.HOLD(pgid)\n", true},
		{"owner called with the boundary real", "m.OWNER(proc)\n", true},
		{"cleanup called with the boundary real", "m.TERMINATE(proc)\n", true},
		{"hold called after the real probe", "module.PROBE()\nmodule.READY=True\nseen=module.HOLD(pgid)\n", false},
		{"hold called under the live prelude", remoteAlphaESProcessIdentityLivePrelude + "seen=module.HOLD(pgid)\n", false},
		{"owner called over the whole boundary", "m.SCAN=scan\nm.SIGNAL=send\nm.IDENTITY=identity\nm.OWNER(proc)\n", false},
		{"owner called over a stand-in cleanup", "m.TERMINATE=controlled\nproc=types.SimpleNamespace(_status_reaped=False)\nm.OWNER(proc)\n", false},
		{"owner called for a reaped child over a stand-in cleanup", "m.TERMINATE=controlled\nproc._status_reaped=True\nm.OWNER(proc)\n", true},
		{"owner called over a stand-in cleanup and hold", "m.TERMINATE=controlled\nm.HOLD=held\nproc._status_reaped=True\nm.OWNER(proc)\n", false},
		{"comparison is no replacement", "ok=module.IDENTITY==original\n", false},
		{"a call is no replacement", "seen=module.SCAN(pgid)\nmodule.SIGNAL(pgid, 15)\n", false},
		// A stand-in for the probe, then an entry point that sets the flag.
		{"probe stand-in then main", "module.PROBE=lambda: None\nstatus=module.main([\"--config\",path])\n", true},
		{"probe stand-in then diagnostic main", "m.PROBE=lambda: None\nm.diagnostic_main()\n", true},
		{"probe stand-in then main as a namespace entry", `namespace["PROBE"] = lambda: None` + "\n" + `namespace["main"]([])` + "\n", true},
		{"probe stand-in then main taken by name", "m.PROBE=lambda: None\nrun=getattr(m,\"main\")\nrun([])\n", true},
		{"probe stand-in then main held in a variable", "m.PROBE=lambda: None\nrun=m.main\nrun([])\n", true},
		{"probe patched with mock then main", `with mock.patch.object(m,"PROBE"):m.main([])` + "\n", true},
		{"probe set with setattr then main", "setattr(module,\"PROBE\",lambda: None)\nmodule.main([])\n", true},
		{"probe backend replaced then main", "module.BACKEND=FakeBackend\nmodule.main([])\n", true},
		{"probe stand-in then main over a stand-in fixed command", "m.PROBE=lambda: None\nm.run_fixed=fixed\nm.main([])\n", false},
		{"probe stand-in then main over a stand-in collection", "m.PROBE=lambda: None\nm.collect=collected\nm.main([])\n", false},
		{"probe stand-in then main over a stand-in diagnosis", "m.PROBE=lambda: None\nm.diagnose_first_rejection=diagnosed\nm.main([])\n", true},
		{"probe stand-in then main over the checks without the chain", "m.PROBE=lambda: None\nm.cert_role=role\nm.key_pair=pair\nm.main([])\n", true},
		{"probe stand-in then main over the checks without the key pair", "m.PROBE=lambda: None\nm.cert_role=role\nm.verify_chain=chain\nm.main([])\n", true},
		{"probe stand-in then main over the checks without the role", "m.PROBE=lambda: None\nm.key_pair=pair\nm.verify_chain=chain\nm.main([])\n", true},
		{"probe stand-in then main over the three checks", "m.PROBE=lambda: None\nm.cert_role=role\nm.key_pair=pair\nm.verify_chain=chain\nm.main([])\n", false},
		{"probe stand-in then diagnostic main over a stand-in collection", "m.PROBE=lambda: None\nm.collect=collected\nm.diagnostic_main()\n", true},
		{"probe stand-in then diagnostic main over a stand-in diagnosis", "m.PROBE=lambda: None\nm.diagnose_first_rejection=diagnosed\nm.diagnostic_main()\n", false},
		{"probe stand-in then diagnostic main over a stand-in fixed command", "m.PROBE=lambda: None\nm.run_fixed=fixed\nm.diagnostic_main()\n", false},
		{"probe stand-in then diagnostic main over the three checks", "m.PROBE=lambda: None\nm.cert_role=role\nm.key_pair=pair\nm.verify_chain=chain\nm.diagnostic_main()\n", false},
		{"probe stand-in then both entry points over a stand-in collection", "m.PROBE=lambda: None\nm.collect=collected\nm.main([])\nm.diagnostic_main()\n", true},
		{"probe stand-in then both entry points over both stand-ins", "m.PROBE=lambda: None\nm.collect=collected\nm.diagnose_first_rejection=diagnosed\nm.main([])\nm.diagnostic_main()\n", false},
		{"probe stand-in then main over the whole boundary", "m.PROBE=lambda: None\nm.SCAN=scan\nm.SIGNAL=send\nm.IDENTITY=identity\nm.main([])\n", false},
		{"probe stand-in and no entry point", "module.PROBE=lambda: None\nmodule.run_fixed((child,))\n", false},
		{"real probe through main", "status=module.main([\"--config\",path])\nassert module.READY is False\n", false},
		{"a name that begins with main", "m.PROBE=lambda: None\nm.maintain(1)\nm.main_count=2\n", false},
		{"the main of another program", "module.PROBE=lambda: None\nchild.write_text(\"def main():pass\\nmain()\\n\")\n", false},
		// setattr with a literal name is a way of replacing as well.
		{"ready set with setattr", "module.PROBE=lambda: None\nsetattr(module,'READY',True)\n", true},
		{"scan set with setattr alone", "setattr(module,\"SCAN\",scan)\n", true},
		{"a pidfd primitive set with setattr alone", "setattr(os,\"PIDFD_OPEN\",opened)\n", true},
	} {
		judged, fault := remoteAlphaESStatusGuardVerdict(names.Replace(tc.text))
		if (judged && fault != "") != tc.refused {
			t.Errorf("rule on %q: judged=%v, fault %q, want refused=%v", tc.name, judged, fault, tc.refused)
		}
	}
	if judged, fault := remoteAlphaESStatusGuardVerdict(remoteAlphaESStatusLocalProcessBoundary); !judged || fault != "" {
		t.Errorf("the shared local boundary: judged=%v, fault %q", judged, fault)
	}

	// The namespace pair, judged as the scan above judges a script.
	if namespaceStandIns < remoteAlphaESStatusNamespaceStandInFloor {
		t.Errorf("guard saw %d scripts with the shared namespace stand-in; want at least %d", namespaceStandIns, remoteAlphaESStatusNamespaceStandInFloor)
	}
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"neither", "module.OPENSSL=str(child)\n", false},
		{"both", "m.CHILD_NS=standin\nm.NS_PROBE=lambda: None\n", false},
		{"both as entries", "namespace[\"CHILD_NS\"] = fake\nnamespace[\"NS_PROBE\"] = fake\n", false},
		{"used and not replaced", "namespace=module.CHILD_NS(backend)\nmodule.NS_PROBE(backend)\n", false},
		{"compared and not replaced", "same=module.CHILD_NS==kept\n", false},
		{"namespace alone", "module.CHILD_NS=type(\"x\",(),{})\n", true},
		{"probe part alone", "module.NS_PROBE=lambda: None\n", true},
		{"namespace entry alone", "namespace[\"CHILD_NS\"] = fake\n", true},
		{"patched probe part alone", "mock.patch.object(module,\"NS_PROBE\",fake)\n", true},
		{"probe part with the namespace only used", "module.NS_PROBE=lambda: None\nmodule.CHILD_NS()\n", true},
		{"namespace alone beside the whole boundary", "m.SCAN=scan\nm.SIGNAL=send\nm.IDENTITY=identity\nm.CHILD_NS=standin\n", true},
		{"both beside the whole boundary", "m.SCAN=scan\nm.SIGNAL=send\nm.IDENTITY=identity\nm.CHILD_NS=standin\nm.NS_PROBE=lambda: None\n", false},
	} {
		judged, fault := remoteAlphaESStatusGuardVerdict(names.Replace(tc.text))
		if (judged && fault != "") != tc.refused {
			t.Errorf("namespace rule on %q: judged=%v, fault %q, want refused=%v", tc.name, judged, fault, tc.refused)
		}
	}
	if judged, fault := remoteAlphaESStatusGuardVerdict(remoteAlphaESStatusLocalChildNamespace); !judged || fault != "" {
		t.Errorf("the shared namespace stand-in: judged=%v, fault %q", judged, fault)
	}
}

// The number of fixture scripts that replace the probe and not the whole
// boundary. It is a floor, as the two numbers beside it.
const remoteAlphaESStatusProbeStandInFloor = 17

// The guard's rule for the entry points rests on how the collector's
// functions reach the fixed command and the cleanup below it. This test holds
// those paths against the collector's source: for each function, every
// top-level definition that names it. A change of the call graph fails here,
// and the guard's rule has to be read again in the same change.
//
// The Python child only parses the source. It does not import it.
func TestRemoteAlphaESServiceTLSStatusLocalBoundaryKnowsTheCallGraph(t *testing.T) {
	const probe = `
import ast,json,sys
source=open(sys.argv[1],encoding="utf-8").read()
tree=ast.parse(source)
wanted=sys.argv[2].split(",")
flag="PROCESS_CAPABILITY_READY"
named={name:set() for name in wanted};defined=set();as_text=set();sets_flag=set();writes_flag=set();module_level=[]
for top in tree.body:
    where=getattr(top,"name","<module>")
    if isinstance(top,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):defined.add(top.name)
    elif any(isinstance(node,ast.Name) and node.id in named for node in ast.walk(top)):module_level.append(ast.get_source_segment(source,top))
    for node in ast.walk(top):
        if isinstance(node,ast.Name) and node.id in named and node.id!=where:named[node.id].add(where)
        if isinstance(node,ast.Attribute) and node.attr in named:named[node.attr].add(where+" (as an attribute)")
        if isinstance(node,ast.Constant) and isinstance(node.value,str) and (node.value in named or node.value==flag):as_text.add(node.value)
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant) and node.value.value is True:
            if any(isinstance(target,ast.Name) and target.id==flag for target in node.targets):sets_flag.add(where)
        if isinstance(node,ast.Name) and node.id==flag and not isinstance(node.ctx,ast.Load):writes_flag.add(where)
        if isinstance(node,ast.Attribute) and node.attr==flag:writes_flag.add(where+" (as an attribute)")
print(json.dumps({"named":{name:sorted(named[name]) for name in wanted},"undefined":sorted(set(wanted)-defined),
                  "as_text":sorted(as_text),"sets_flag":sorted(sets_flag),"writes_flag":sorted(writes_flag),
                  "module_level":module_level},sort_keys=True))
`
	want := map[string][]string{
		// The entry points, which nothing in the collector calls.
		"main":            {"<module>"},
		"diagnostic_main": {},
		// From each entry point to the three checks that run the fixed command.
		"collect":                  {"main"},
		"diagnose_first_rejection": {"diagnostic_main"},
		"cert_role":                {"collect", "diagnose_first_rejection"},
		"key_pair":                 {"collect", "diagnose_first_rejection"},
		"verify_chain":             {"collect", "diagnose_first_rejection"},
		"cert_metadata":            {"cert_role"},
		"run_fixed":                {"cert_metadata", "cert_role", "key_pair", "verify_chain"},
		// run_fixed opens the PID namespace of the fixed command and runs it
		// inside, through _run_fixed_in_namespace.
		"_run_fixed_in_namespace": {"run_fixed"},
		"ChildNamespace":          {"_run_fixed_in_namespace", "run_fixed", "validate_child_namespace"},
		// From the fixed command to the boundary.
		"own_child_until_proved":    {"_run_fixed_in_namespace"},
		"terminate_child":           {"own_child_until_proved"},
		"prove_group_absent":        {"own_child_until_proved", "terminate_child"},
		"scan_group_members":        {"ProcessCapabilityBackend", "prove_group_absent", "signal_same_group_members", "terminate_child"},
		"signal_same_group_members": {"terminate_child"},
		"read_proc_identity":        {"ProcessCapabilityBackend", "prove_group_absent", "scan_group_members", "signal_same_group_members"},
		// The probe and its backend.
		"validate_process_capability": {"diagnostic_main", "main"},
		"ProcessCapabilityBackend":    {"validate_process_capability"},
		// The namespace part of the probe, which only the probe runs.
		"validate_child_namespace": {"validate_process_capability"},
	}
	var names []string
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath(), strings.Join(names, ","))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("call graph probe: %v\n%s", err, output)
	}
	var got struct {
		Named       map[string][]string `json:"named"`
		Undefined   []string            `json:"undefined"`
		AsText      []string            `json:"as_text"`
		SetsFlag    []string            `json:"sets_flag"`
		WritesFlag  []string            `json:"writes_flag"`
		ModuleLevel []string            `json:"module_level"`
	}
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("call graph probe JSON: %v\n%s", err, output)
	}
	for _, name := range names {
		if strings.Join(got.Named[name], ", ") != strings.Join(want[name], ", ") {
			t.Errorf("%s is named in [%s], and the guard's rule was written for [%s]",
				name, strings.Join(got.Named[name], ", "), strings.Join(want[name], ", "))
		}
	}
	if len(got.Undefined) != 0 {
		t.Errorf("the collector does not define %v at its top level", got.Undefined)
	}
	// A function that is reached by its name as text would not show above.
	if len(got.AsText) != 0 {
		t.Errorf("the collector holds %v as text", got.AsText)
	}
	// Outside the definitions, the collector names one of these functions in
	// one statement only: it runs main when it is run as a program. A second
	// name for a function, given at the top level, would show here.
	const runAsProgram = "if __name__ == \"__main__\":\n    sys.exit(main(sys.argv[1:]))"
	if len(got.ModuleLevel) != 1 || got.ModuleLevel[0] != runAsProgram {
		t.Errorf("outside its definitions the collector names these functions in %q, and the guard's rule was written for %q", got.ModuleLevel, runAsProgram)
	}
	// The flag is false at the top level, and only the two entry points set
	// it. Nothing else writes it, under its name or as an attribute.
	if strings.Join(got.SetsFlag, ", ") != "diagnostic_main, main" {
		t.Errorf("the capability flag is set in %v, and the guard's rule was written for diagnostic_main and main", got.SetsFlag)
	}
	if strings.Join(got.WritesFlag, ", ") != "<module>, diagnostic_main, main" {
		t.Errorf("the capability flag is written in %v, and the guard's rule was written for <module>, diagnostic_main and main", got.WritesFlag)
	}
}

// The number of fixture scripts that hold the shared namespace stand-in. It
// is a floor, as the two numbers above.
const remoteAlphaESStatusNamespaceStandInFloor = 36

// runRemoteAlphaESStatusLocalBoundaryProbe runs one Python child that loads
// only the source-controlled collector and returns its exit status and
// output. The child runs no entry point, operator route, or real OpenSSL
// child, and writes nothing outside the given directory.
func runRemoteAlphaESStatusLocalBoundaryProbe(t *testing.T, probe string, args ...string) (int, string) {
	t.Helper()
	// Longer than the bound of the local boundary, so that a fixture that
	// has to be ended by its own bound still shows its status and stack.
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	argv := append([]string{"-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath()}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", argv...)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.WaitDelay = 10 * time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("local boundary probe timed out: %v\n%s", ctx.Err(), output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("local boundary probe: %v\n%s", err, output)
	}
	return 0, string(output)
}

// The Python lines that take the target-only facilities away from the fixture
// process before the collector is used: no /proc entry can be opened or
// listed, and the pidfd operations do not exist. This is what the collector
// meets on a host without them. It is a stand-in for such a host, not a run
// on one.
const remoteAlphaESStatusLocalBoundaryLoader = `
import importlib.util,json,os,pathlib,signal,sys,time
spec=importlib.util.spec_from_file_location("status_local_boundary",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2])
def deny_target_facilities():
    real_open=os.open;real_listdir=os.listdir
    def target(path):
        return isinstance(path,(str,bytes)) and os.fsdecode(path).rstrip("/").split("/")[:2]==["","proc"]
    def no_open(path,*args,**kwargs):
        if target(path):raise FileNotFoundError(2,"no /proc on this host",os.fsdecode(path))
        return real_open(path,*args,**kwargs)
    def no_listdir(path="."):
        if target(path):raise FileNotFoundError(2,"no /proc on this host",os.fsdecode(path))
        return real_listdir(path)
    os.open=no_open;os.listdir=no_listdir
    for owner,name in ((os,"pidfd_open"),(signal,"pidfd_send_signal")):
        if hasattr(owner,name):delattr(owner,name)
def fixed_child(name,body):
    child=root/name;child.write_text("#!/usr/bin/python3\n"+body);child.chmod(0o700);return str(child)
`

// The same loader for a fixture that never imports os. The shared boundary
// has to bring what it uses itself; the last line fails the fixture when the
// name exists after all.
const remoteAlphaESStatusLocalBoundaryLoaderWithoutOS = `
import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location("status_local_boundary",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2])
def fixed_child(name,body):
    child=root/name;child.write_text("#!/usr/bin/python3\n"+body);child.chmod(0o700);return str(child)
assert "os" not in globals()
`

// One fixed child that ends by itself, run through the collector.
const remoteAlphaESStatusLocalBoundaryRun = `
module.CHILD_GRACE=0.5
child=fixed_child("plain","import sys\nsys.stdout.write('fixed')\n");module.OPENSSL=child
print(repr(module.run_fixed((child,"version"))))
`

// The shared local boundary must need nothing of the target: with /proc and
// the pidfd operations denied, a fixed child still runs and its cleanup
// returns, for a child that ends by itself, for a child that leaves a
// process in its group, and for a child that the collector has to stop.
func TestRemoteAlphaESServiceTLSStatusLocalBoundaryNeedsNoTargetFacility(t *testing.T) {
	const probe = remoteAlphaESStatusLocalBoundaryLoader + `
LOCAL_FIXTURE_BOUND=60.0
` + remoteAlphaESStatusLocalProcessBoundary + `
deny_target_facilities()
module.CHILD_GRACE=0.5;module.CHILD_TIMEOUT=1.5
cases={}
def run(label,child,want):
    module.OPENSSL=child
    began=time.monotonic()
    try:seen=module.run_fixed((child,"version"))
    except BaseException as exc:seen=type(exc).__name__+":"+str(exc)
    cases[label]={"passed":seen==want,"seen":repr(seen),"seconds":round(time.monotonic()-began,3),
                  "closeout_unproved":module.WITNESS_DISPOSITION_UNPROVED}
run("ends_by_itself",fixed_child("plain","import sys\nsys.stdout.write('fixed')\n"),(0,b"fixed",b""))
run("leaves_a_group_member",fixed_child("leaves",
    "import os,sys,time\nif os.fork()==0:\n    for fd in (0,1,2):os.close(fd)\n    time.sleep(30);os._exit(0)\nsys.stdout.write('fixed')\n"),
    (0,b"fixed",b""))
run("has_to_be_stopped",fixed_child("stays","import time\ntime.sleep(30)\n"),"Incomplete:child_timeout")
print(json.dumps(cases,sort_keys=True))
`
	status, output := runRemoteAlphaESStatusLocalBoundaryProbe(t, probe, t.TempDir())
	if status != 0 {
		t.Fatalf("probe ended with status %d:\n%s", status, output)
	}
	for _, label := range []string{"ends_by_itself", "leaves_a_group_member", "has_to_be_stopped"} {
		if !strings.Contains(output, `"`+label+`": {"closeout_unproved": false, "passed": true`) {
			t.Errorf("%s did not pass with the target-only facilities denied:\n%s", label, output)
		}
	}
}

// Without the identity stand-in the same fixture has no end on such a host:
// this is the fault that the shared boundary exists to exclude. The test
// proves that the two other tests of this file can see it, by taking the one
// line away. The bound then ends the fixture with status 98 and the stack of
// the absence hold, and a target-only reader that is reached ends it with
// status 97. Both also hold in a fixture that never imports os, because the
// boundary brings what it uses. The last case leaves the bound at its
// default: the timer has to be armed, with no more than the 120 seconds that
// the comment of the boundary names.
func TestRemoteAlphaESServiceTLSStatusLocalFixtureFailsBounded(t *testing.T) {
	line := fmt.Sprintf("module.%s=lambda pid: None\n", "read_proc_identity")
	if strings.Count(remoteAlphaESStatusLocalProcessBoundary, line) != 1 {
		t.Fatalf("the shared local boundary does not hold the identity stand-in exactly once")
	}
	partial := strings.Replace(remoteAlphaESStatusLocalProcessBoundary, line, "", 1)
	if judged, fault := remoteAlphaESStatusGuardVerdict(partial); !judged || !strings.Contains(fault, "read_proc_identity") {
		t.Errorf("the guard accepts the boundary without its identity stand-in: judged=%v, fault %q", judged, fault)
	}
	// The hold has no end when neither reader below the identity reader can
	// answer. These two lines put that in the place of the two tripwires.
	const neverAbsent = "module.read_proc_stat_identity=lambda pid: None\nmodule.process_absent=lambda pid: (_ for _ in ()).throw(module.Incomplete('process_capability_unavailable'))\n"
	for _, tc := range []struct {
		name, probe string
		status      int
		want        []string
	}{
		{"overdue", strings.Join([]string{remoteAlphaESStatusLocalBoundaryLoader, "LOCAL_FIXTURE_BOUND=3.0\n", partial, neverAbsent,
			"deny_target_facilities()\n", remoteAlphaESStatusLocalBoundaryRun}, ""), 98,
			[]string{"local fixture exceeded its bound", "prove_group_absent"}},
		{"target path", strings.Join([]string{remoteAlphaESStatusLocalBoundaryLoader, partial, "deny_target_facilities()\n", remoteAlphaESStatusLocalBoundaryRun}, ""), 97,
			[]string{"local fixture reached the target-only host path: read_proc_stat_identity"}},
		{"whole", remoteAlphaESStatusLocalBoundaryLoader + remoteAlphaESStatusLocalProcessBoundary + "deny_target_facilities()\n" + remoteAlphaESStatusLocalBoundaryRun, 0,
			[]string{"(0, b'fixed', b'')"}},
		{"overdue without os", strings.Join([]string{remoteAlphaESStatusLocalBoundaryLoaderWithoutOS, "LOCAL_FIXTURE_BOUND=3.0\n", partial, neverAbsent,
			remoteAlphaESStatusLocalBoundaryRun}, ""), 98,
			[]string{"local fixture exceeded its bound", "prove_group_absent"}},
		{"target path without os", strings.Join([]string{remoteAlphaESStatusLocalBoundaryLoaderWithoutOS, partial, remoteAlphaESStatusLocalBoundaryRun}, ""), 97,
			[]string{"local fixture reached the target-only host path: read_proc_stat_identity"}},
		{"whole without os", remoteAlphaESStatusLocalBoundaryLoaderWithoutOS + remoteAlphaESStatusLocalProcessBoundary + remoteAlphaESStatusLocalBoundaryRun, 0,
			[]string{"(0, b'fixed', b'')"}},
		{"default bound", remoteAlphaESStatusLocalBoundaryLoader + remoteAlphaESStatusLocalProcessBoundary +
			"left,again=signal.getitimer(signal.ITIMER_REAL);signal.setitimer(signal.ITIMER_REAL,0)\n" +
			"print('armed once' if 100.0<left<=120.0 and again==0.0 else 'the default bound is not armed: %r'%((left,again),))\n", 0,
			[]string{"armed once"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			began := time.Now()
			status, output := runRemoteAlphaESStatusLocalBoundaryProbe(t, tc.probe, t.TempDir())
			if status != tc.status {
				t.Fatalf("status %d, want %d:\n%s", status, tc.status, output)
			}
			for _, want := range tc.want {
				if !strings.Contains(output, want) {
					t.Errorf("output lacks %q:\n%s", want, output)
				}
			}
			if strings.Contains(output, "NameError") {
				t.Errorf("the fixture ended on a missing name:\n%s", output)
			}
			if elapsed := time.Since(began); elapsed > 60*time.Second {
				t.Errorf("took %s", elapsed)
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusLocalBoundaryDocumentsContract(t *testing.T) {
	doc := mustRead(t, filepath.Join(executionSubstrateRepoRoot, ".docs", "system_overview", "capability_probing.md"))
	section := compactDocSection(t, doc, "Root-package tests of the Remote Alpha TLS status collector", "")
	for _, want := range []string{
		"two kinds of fixture, and never a mixture",
		"skips with an explicit reason when that read is refused",
		"It never decides by an operating-system label, and it sets the capability flag only after the collector's real process-capability probe has passed.",
		"`scan_group_members`, `signal_same_group_members`, and `read_proc_identity`",
		"each either by a stand-in for the function or by stand-ins for the operating-system primitives that the function uses",
		"A fixture must not replace only part of that boundary.",
		"A stand-in for the probe alone is the same partial replacement.",
		"The collector's entry points run the probe and then declare the capability themselves",
		"it replaces the whole boundary, or it replaces a function on every path from that entry point to the fixed command, so that no fixed child is started",
		"one more test holds those paths against the collector's source",
		"It imports what it uses itself",
		"neither `/proc` nor `pidfd_open`",
		"the group-absence hold never returns",
		"one shared test constant",
		"fails one test and does not stop the test binary",
		"with `/proc` and the pidfd operations denied",
		"This is test hygiene only. It changes no collector behavior, capability criterion, hold, signal, reap, lock, or publication rule.",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("capability_probing.md lacks %q in the collector fixture rule", want)
		}
	}
}
