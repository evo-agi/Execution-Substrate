package main

import (
	"os"

	"execution-platform/es/runtimehelper"
)

func main() {
	os.Exit(runtimehelper.Main(os.Args[1:]))
}
