package runtimehelper

import (
	"errors"
	"fmt"
	"os"
)

func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: es-runtime-support <supervisor|helper|exec-workload> [...]")
		return 2
	}

	var err error
	switch args[0] {
		case "supervisor":
			err = runSupervisor(args[1:])
		case "helper":
			err = runHelper(args[1:])
		case "exec-workload":
			err = runExecWorkload(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[0])
			return 2
	}

	if err == nil {
		return 0
	}

	var exitErr *exitError
	if errors.As(err, &exitErr) {
		if exitErr.err != nil {
			fmt.Fprintln(os.Stderr, exitErr.err)
		}
		return exitErr.code
	}

	fmt.Fprintln(os.Stderr, err)
	return 1
}
