package app_test

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
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
// listens on it over TCP or UDP (Nomad's Serf port uses both).
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
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if err != nil {
			return 0, fmt.Errorf("read the kernel's ephemeral port range: %w", err)
		}
		if err := checkTestPortRangeOutside(string(raw), testPortRangeLow, testPortRangeHigh); err != nil {
			return 0, err
		}
	}
	return reserveTestPortIn(testPortRangeLow, testPortRangeHigh, rand.IntN(testPortRangeHigh-testPortRangeLow))
}

// checkTestPortRangeOutside refuses a test port range [low, high) that
// overlaps the ephemeral range given in the format of
// /proc/sys/net/ipv4/ip_local_port_range ("first last").
func checkTestPortRangeOutside(ephemeral string, low, high int) error {
	fields := strings.Fields(ephemeral)
	if len(fields) != 2 {
		return fmt.Errorf("ephemeral port range %q is not two numbers", ephemeral)
	}
	first, err := strconv.Atoi(fields[0])
	if err != nil {
		return fmt.Errorf("ephemeral port range %q: %w", ephemeral, err)
	}
	last, err := strconv.Atoi(fields[1])
	if err != nil {
		return fmt.Errorf("ephemeral port range %q: %w", ephemeral, err)
	}
	if first < high && last >= low {
		return fmt.Errorf("the kernel's ephemeral port range %d-%d overlaps the test port range %d-%d, so a test port could be taken before its service binds it; set net.ipv4.ip_local_port_range to start at %d or above", first, last, low, high-1, high)
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
	var ephemeralFirst, ephemeralLast int
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if err != nil {
			t.Fatalf("read ephemeral port range: %v", err)
		}
		if _, err := fmt.Sscan(string(raw), &ephemeralFirst, &ephemeralLast); err != nil {
			t.Fatalf("parse ephemeral port range %q: %v", raw, err)
		}
	}

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		port, err := reserveTCPPortValue()
		if err != nil {
			t.Fatalf("reserve port %d: %v", i, err)
		}
		if port < testPortRangeLow || port >= testPortRangeHigh {
			t.Fatalf("port %d is outside the test port range %d-%d", port, testPortRangeLow, testPortRangeHigh-1)
		}
		if ephemeralLast != 0 && port >= ephemeralFirst && port <= ephemeralLast {
			t.Fatalf("port %d is in the kernel's ephemeral range %d-%d", port, ephemeralFirst, ephemeralLast)
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
		ephemeral string
		ok        bool
	}{
		{"32768\t60999\n", true},
		{"20000 60999", true},
		{"1024 9999", true},
		{"19999 60999", false},
		{"1024 65535", false},
		{"15000 16000", false},
		{"1024 10000", false},
		{"32768", false},
		{"a b", false},
	}
	for _, tc := range cases {
		err := checkTestPortRangeOutside(tc.ephemeral, testPortRangeLow, testPortRangeHigh)
		if (err == nil) != tc.ok {
			t.Errorf("checkTestPortRangeOutside(%q) = %v, want ok=%v", tc.ephemeral, err, tc.ok)
		}
	}
}
