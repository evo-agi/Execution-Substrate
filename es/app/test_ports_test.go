package app_test

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Tests that start real services (ARS, EGS, AGS, ES, Nomad, a mock Vault)
// have to write each service's port into its configuration before the
// service starts, often from a script that the test does not control. A port
// chosen by listening on port 0 and closing the listener again comes from the
// kernel's ephemeral range, which the kernel also hands to every other
// socket that binds port 0 and to the local end of outgoing connections. In
// the time between the check and the service's own bind, the port can be
// taken, and the service then fails to start. Two such reservations in a row
// can also return the same port.
//
// reserveTCPPortValue therefore hands out ports from testPortRangeLow to
// testPortRangeHigh-1 instead. The range lies below the kernel's ephemeral
// range (Linux's default is 32768-60999; macOS and Windows use 49152-65535)
// and below Nomad's default range for dynamic task ports (20000-32000), so
// nothing takes one of these ports unless it binds that exact port. Each
// port is handed out at most once per test process, and only when nothing
// listens on it over TCP or UDP (Nomad's Serf port uses both). Before it
// hands out any port, it reads the kernel's actual ephemeral range and
// refuses if that range overlaps the test range or cannot be read.
const (
	testPortRangeLow  = 10000
	testPortRangeHigh = 20000
)

var testPorts = struct {
	sync.Mutex
	handedOut map[int]bool
}{handedOut: map[int]bool{}}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	port, err := reserveTCPPortValue()
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	return port
}

func reserveTCPPortValue() (int, error) {
	return reserveTestPort(ephemeralPortRange)
}

// reserveTestPort hands out a port from the test range, but only after the
// ephemeral range, as ephemeralRange reports it, is shown to lie outside it.
func reserveTestPort(ephemeralRange func() (portRange, error)) (int, error) {
	ephemeral, err := ephemeralRange()
	if err != nil {
		return 0, err
	}
	if err := checkTestPortRangeOutside(ephemeral, testPortRangeLow, testPortRangeHigh); err != nil {
		return 0, err
	}
	return reserveTestPortIn(testPortRangeLow, testPortRangeHigh, rand.IntN(testPortRangeHigh-testPortRangeLow))
}

// portRange is an inclusive port range first-last, read from source.
type portRange struct {
	first, last int
	source      string
}

// ephemeralPortRange reads the kernel's ephemeral port range once per test
// process, from the first of these resources that exists: the procfs file
// that Linux publishes it in, or the net.inet.ip.portrange sysctl keys that
// macOS and the BSDs publish it under. When neither exists, or the one that
// exists cannot be read or parsed, it returns an error: the test range cannot
// then be shown to be outside the ephemeral range.
var ephemeralPortRange = sync.OnceValues(func() (portRange, error) {
	return readEphemeralPortRange("/proc/sys/net/ipv4/ip_local_port_range", func() ([]byte, error) {
		return exec.Command("sysctl", "-n", "net.inet.ip.portrange.first", "net.inet.ip.portrange.last").Output()
	})
})

// readEphemeralPortRange reads the ephemeral port range from the file at
// procPath, or, only when that file does not exist, from the output of
// sysctl.
func readEphemeralPortRange(procPath string, sysctl func() ([]byte, error)) (portRange, error) {
	raw, err := os.ReadFile(procPath)
	if err == nil {
		first, last, err := parsePortRange(string(raw))
		if err != nil {
			return portRange{}, fmt.Errorf("%s: %w", procPath, err)
		}
		return portRange{first, last, procPath}, nil
	}
	if !os.IsNotExist(err) {
		return portRange{}, fmt.Errorf("read the kernel's ephemeral port range: %w", err)
	}
	const sysctlSource = "sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last"
	output, sysctlErr := sysctl()
	if sysctlErr != nil {
		return portRange{}, fmt.Errorf("cannot read the kernel's ephemeral port range: %s does not exist (%v) and %s failed (%v), so the test port range cannot be shown to be outside it", procPath, err, sysctlSource, sysctlErr)
	}
	first, last, err := parsePortRange(string(output))
	if err != nil {
		return portRange{}, fmt.Errorf("%s: %w", sysctlSource, err)
	}
	return portRange{first, last, sysctlSource}, nil
}

// parsePortRange reads a port range written as two numbers separated by
// white space, as the procfs file and the two sysctl values are.
func parsePortRange(text string) (int, int, error) {
	fields := strings.Fields(text)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("ephemeral port range %q is not two numbers", text)
	}
	first, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, fmt.Errorf("ephemeral port range %q: %w", text, err)
	}
	last, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("ephemeral port range %q: %w", text, err)
	}
	if first > last {
		return 0, 0, fmt.Errorf("ephemeral port range %q starts after it ends", text)
	}
	return first, last, nil
}

// checkTestPortRangeOutside refuses a test port range [low, high) that
// overlaps the ephemeral range.
func checkTestPortRangeOutside(ephemeral portRange, low, high int) error {
	if ephemeral.first < high && ephemeral.last >= low {
		return fmt.Errorf("the kernel's ephemeral port range %d-%d (from %s) overlaps the test port range %d-%d, so a test port could be taken before its service binds it; move the ephemeral range to start at %d or above", ephemeral.first, ephemeral.last, ephemeral.source, low, high-1, high)
	}
	return nil
}

// reserveTestPortIn returns the first port in [low, high), starting at
// low+offset and wrapping around, that this process has not handed out yet
// and that is free for TCP and UDP on all addresses.
func reserveTestPortIn(low, high, offset int) (int, error) {
	testPorts.Lock()
	defer testPorts.Unlock()

	size := high - low
	for i := 0; i < size; i++ {
		port := low + (offset+i)%size
		if testPorts.handedOut[port] || !testPortFree(port) {
			continue
		}
		testPorts.handedOut[port] = true
		return port, nil
	}
	return 0, fmt.Errorf("no free port left in the test port range %d-%d", low, high-1)
}

func testPortFree(port int) bool {
	address := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return false
	}
	defer listener.Close()
	packetConn, err := net.ListenPacket("udp4", address)
	if err != nil {
		return false
	}
	defer packetConn.Close()
	return true
}

func TestReserveTCPPortValueHandsOutDistinctPortsOutsideTheEphemeralRange(t *testing.T) {
	ephemeral, err := ephemeralPortRange()
	if err != nil {
		t.Fatalf("read ephemeral port range: %v", err)
	}
	t.Logf("ephemeral port range %d-%d from %s", ephemeral.first, ephemeral.last, ephemeral.source)

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		port, err := reserveTCPPortValue()
		if err != nil {
			t.Fatalf("reserve port %d: %v", i, err)
		}
		if port < testPortRangeLow || port >= testPortRangeHigh {
			t.Fatalf("port %d is outside the test port range %d-%d", port, testPortRangeLow, testPortRangeHigh-1)
		}
		if port >= ephemeral.first && port <= ephemeral.last {
			t.Fatalf("port %d is in the kernel's ephemeral range %d-%d", port, ephemeral.first, ephemeral.last)
		}
		if seen[port] {
			t.Fatalf("port %d was handed out twice", port)
		}
		seen[port] = true
	}
}

func TestReserveTestPortInSkipsPortsInUse(t *testing.T) {
	// Find two adjacent ports that are free for this test, then occupy the
	// first over TCP and check that it is skipped; then the same over UDP.
	for _, network := range []string{"tcp4", "udp4"} {
		t.Run(network, func(t *testing.T) {
			low, err := reserveTCPPortValue()
			if err != nil {
				t.Fatalf("reserve first port: %v", err)
			}
			address := net.JoinHostPort("0.0.0.0", strconv.Itoa(low))
			var closer interface{ Close() error }
			if network == "tcp4" {
				closer, err = net.Listen(network, address)
			} else {
				closer, err = net.ListenPacket(network, address)
			}
			if err != nil {
				t.Fatalf("occupy %s port %d: %v", network, low, err)
			}
			defer closer.Close()

			// Unmark the occupied port for the call below, so that only the
			// listener above can make the allocator skip it; mark it again
			// afterwards so that no later test gets it.
			testPorts.Lock()
			delete(testPorts.handedOut, low)
			testPorts.Unlock()
			defer func() {
				testPorts.Lock()
				testPorts.handedOut[low] = true
				testPorts.Unlock()
			}()

			port, err := reserveTestPortIn(low, low+1, 0)
			if err == nil {
				t.Fatalf("reserveTestPortIn returned port %d, which is in use over %s", port, network)
			}
		})
	}
}

func TestReserveTestPortInNeverHandsOutAPortTwice(t *testing.T) {
	first, err := reserveTCPPortValue()
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	if port, err := reserveTestPortIn(first, first+1, 0); err == nil {
		t.Fatalf("reserveTestPortIn handed out port %d a second time", port)
	}
}

func TestCheckTestPortRangeOutsideRefusesAnOverlap(t *testing.T) {
	cases := []struct {
		text string
		ok   bool
	}{
		{"32768\t60999\n", true},
		{"49152\n65535\n", true},
		{"20000 60999", true},
		{"1024 9999", true},
		{"19999 60999", false},
		{"1024 65535", false},
		{"15000 16000", false},
		{"1024 10000", false},
	}
	for _, tc := range cases {
		first, last, err := parsePortRange(tc.text)
		if err != nil {
			t.Fatalf("parsePortRange(%q): %v", tc.text, err)
		}
		err = checkTestPortRangeOutside(portRange{first, last, "test"}, testPortRangeLow, testPortRangeHigh)
		if (err == nil) != tc.ok {
			t.Errorf("checkTestPortRangeOutside(%q) = %v, want ok=%v", tc.text, err, tc.ok)
		}
	}
	for _, text := range []string{"32768", "a b", "1 2 3", "", "60999 32768"} {
		if _, _, err := parsePortRange(text); err == nil {
			t.Errorf("parsePortRange(%q) accepted malformed text", text)
		}
	}
}

func TestReadEphemeralPortRangeProbesProcfsThenSysctlAndFailsWithoutEither(t *testing.T) {
	dir := t.TempDir()
	procFile := filepath.Join(dir, "ip_local_port_range")
	if err := os.WriteFile(procFile, []byte("32768\t60999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformedFile := filepath.Join(dir, "malformed")
	if err := os.WriteFile(malformedFile, []byte("32768\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	sysctlCalled := false
	sysctlOK := func() ([]byte, error) {
		sysctlCalled = true
		return []byte("49152\n65535\n"), nil
	}
	sysctlMissing := func() ([]byte, error) {
		sysctlCalled = true
		return nil, exec.ErrNotFound
	}
	sysctlMalformed := func() ([]byte, error) {
		sysctlCalled = true
		return []byte("unknown oid\n"), nil
	}

	cases := []struct {
		name       string
		procPath   string
		sysctl     func() ([]byte, error)
		want       portRange
		wantSysctl bool
		wantErr    bool
	}{
		{"procfs file is used and sysctl is not run", procFile, sysctlOK, portRange{32768, 60999, procFile}, false, false},
		{"sysctl is used when the procfs file does not exist", missing, sysctlOK, portRange{49152, 65535, "sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last"}, true, false},
		{"neither resource fails", missing, sysctlMissing, portRange{}, true, true},
		{"unreadable procfs path fails without falling back", dir, sysctlOK, portRange{}, false, true},
		{"malformed procfs file fails without falling back", malformedFile, sysctlOK, portRange{}, false, true},
		{"malformed sysctl output fails", missing, sysctlMalformed, portRange{}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sysctlCalled = false
			got, err := readEphemeralPortRange(tc.procPath, tc.sysctl)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readEphemeralPortRange() error = %v, want error %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("readEphemeralPortRange() = %+v, want %+v", got, tc.want)
			}
			if sysctlCalled != tc.wantSysctl {
				t.Fatalf("sysctl run = %v, want %v", sysctlCalled, tc.wantSysctl)
			}
		})
	}
}

func TestReserveTestPortRefusesWhenTheEphemeralRangeOverlapsOrCannotBeRead(t *testing.T) {
	overlapping := func() (portRange, error) { return portRange{15000, 16000, "fake"}, nil }
	if port, err := reserveTestPort(overlapping); err == nil {
		t.Fatalf("reserveTestPort handed out port %d while the ephemeral range overlaps the test range", port)
	}
	unreadable := func() (portRange, error) { return portRange{}, fmt.Errorf("fake: cannot read") }
	if port, err := reserveTestPort(unreadable); err == nil {
		t.Fatalf("reserveTestPort handed out port %d while the ephemeral range cannot be read", port)
	}
	outside := func() (portRange, error) { return portRange{32768, 60999, "fake"}, nil }
	port, err := reserveTestPort(outside)
	if err != nil {
		t.Fatalf("reserveTestPort with the ephemeral range outside the test range: %v", err)
	}
	if port < testPortRangeLow || port >= testPortRangeHigh {
		t.Fatalf("port %d is outside the test port range %d-%d", port, testPortRangeLow, testPortRangeHigh-1)
	}
}
