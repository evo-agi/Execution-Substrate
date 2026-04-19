//go:build linux

package runtimehelper

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type privilegeSnapshot struct {
	CapEff     string
	CapPrm     string
	CapAmb     string
	CapBnd     string
	NoNewPrivs bool
	SuppGroups []int
}

func dropHelperSteadyStatePrivileges() (privilegeSnapshot, error) {
	_ = setNoNewPrivsAllThreads()
	if err := clearAmbientCapabilitiesAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}
	if err := dropBoundingCapabilitiesAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}
	if err := setCapabilitySetsEmptyAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}

	snapshot, err := readPrivilegeSnapshot()
	if err != nil {
		return privilegeSnapshot{}, err
	}
	if snapshot.CapEff != "0000000000000000" || snapshot.CapPrm != "0000000000000000" || snapshot.CapAmb != "0000000000000000" {
		return privilegeSnapshot{}, fmt.Errorf(
			"helper active capabilities remain after steady-state drop: cap_eff=%s cap_prm=%s cap_amb=%s cap_bnd=%s",
			snapshot.CapEff,
			snapshot.CapPrm,
			snapshot.CapAmb,
			snapshot.CapBnd,
		)
	}
	return snapshot, nil
}

func prepareWorkloadBoundary(uid int, gid int) (privilegeSnapshot, error) {
	if err := syscall.Setgroups([]int{}); err != nil {
		return privilegeSnapshot{}, fmt.Errorf("clear supplemental groups: %w", err)
	}
	if err := clearAmbientCapabilitiesAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}
	if err := dropBoundingCapabilitiesAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}
	if err := setNoNewPrivsAllThreads(); err != nil {
		return privilegeSnapshot{}, err
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return privilegeSnapshot{}, fmt.Errorf("drop workload gid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return privilegeSnapshot{}, fmt.Errorf("drop workload uid: %w", err)
	}

	snapshot, err := readPrivilegeSnapshot()
	if err != nil {
		return privilegeSnapshot{}, err
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return privilegeSnapshot{}, fmt.Errorf("workload credentials were not dropped to %d:%d", uid, gid)
	}
	if len(snapshot.SuppGroups) != 0 {
		return privilegeSnapshot{}, fmt.Errorf("workload supplemental groups remain after drop: %v", snapshot.SuppGroups)
	}
	if !snapshot.NoNewPrivs {
		return privilegeSnapshot{}, fmt.Errorf("workload no_new_privs is not set")
	}
	if snapshot.CapEff != "0000000000000000" || snapshot.CapPrm != "0000000000000000" || snapshot.CapAmb != "0000000000000000" || snapshot.CapBnd != "0000000000000000" {
		return privilegeSnapshot{}, fmt.Errorf("workload capabilities remain after drop")
	}
	return snapshot, nil
}

func setNoNewPrivsAllThreads() error {
	if _, _, err := syscall.AllThreadsSyscall6(
		syscall.SYS_PRCTL,
		uintptr(unix.PR_SET_NO_NEW_PRIVS),
		1,
		0,
		0,
		0,
		0,
	); err != 0 {
		return fmt.Errorf("set no_new_privs across threads: %w", err)
	}
	return nil
}

func clearAmbientCapabilitiesAllThreads() error {
	if _, _, err := syscall.AllThreadsSyscall6(
		syscall.SYS_PRCTL,
		uintptr(unix.PR_CAP_AMBIENT),
		uintptr(unix.PR_CAP_AMBIENT_CLEAR_ALL),
		0,
		0,
		0,
		0,
	); err != 0 {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	return nil
}

func dropBoundingCapabilitiesAllThreads() error {
	lastCapBytes, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return fmt.Errorf("read cap_last_cap: %w", err)
	}
	lastCap, err := strconv.Atoi(strings.TrimSpace(string(lastCapBytes)))
	if err != nil {
		return fmt.Errorf("parse cap_last_cap: %w", err)
	}
	for capability := 0; capability <= lastCap; capability++ {
		if _, _, err := syscall.AllThreadsSyscall6(
			syscall.SYS_PRCTL,
			uintptr(unix.PR_CAPBSET_DROP),
			uintptr(capability),
			0,
			0,
			0,
			0,
		); err != 0 {
			return fmt.Errorf("drop bounding capability %d: %w", capability, err)
		}
	}
	return nil
}

func setCapabilitySetsEmptyAllThreads() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if _, _, err := syscall.AllThreadsSyscall(
		syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	); err != 0 {
		return fmt.Errorf("capset empty across threads: %w", err)
	}
	return nil
}

func readPrivilegeSnapshot() (privilegeSnapshot, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return privilegeSnapshot{}, fmt.Errorf("open /proc/self/status: %w", err)
	}
	defer file.Close()

	snapshot := privilegeSnapshot{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
			case strings.HasPrefix(line, "CapEff:"):
				snapshot.CapEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			case strings.HasPrefix(line, "CapPrm:"):
				snapshot.CapPrm = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
			case strings.HasPrefix(line, "CapAmb:"):
				snapshot.CapAmb = strings.TrimSpace(strings.TrimPrefix(line, "CapAmb:"))
			case strings.HasPrefix(line, "CapBnd:"):
				snapshot.CapBnd = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
			case strings.HasPrefix(line, "NoNewPrivs:"):
				snapshot.NoNewPrivs = strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:")) == "1"
		}
	}
	if err := scanner.Err(); err != nil {
		return privilegeSnapshot{}, fmt.Errorf("scan /proc/self/status: %w", err)
	}

	groups, err := unix.Getgroups()
	if err != nil {
		return privilegeSnapshot{}, fmt.Errorf("read supplemental groups: %w", err)
	}
	snapshot.SuppGroups = groups
	return snapshot, nil
}
