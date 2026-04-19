package main

import (
	"os"

	"execution-substrate/es/runtimehelper"
)

func main() {
	os.Exit(runtimehelper.Main(os.Args[1:]))
}
