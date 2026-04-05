//go:build !linux

package runtimehelper

import "fmt"

type privilegeSnapshot struct {
	CapEff     string
	CapPrm     string
	CapAmb     string
	CapBnd     string
	NoNewPrivs bool
	SuppGroups []int
}

func dropHelperSteadyStatePrivileges() (privilegeSnapshot, error) {
	return privilegeSnapshot{}, fmt.Errorf("runtime helper privilege dropping requires linux")
}

func prepareWorkloadBoundary(uid int, gid int) (privilegeSnapshot, error) {
	return privilegeSnapshot{}, fmt.Errorf("workload privilege boundary requires linux")
}
