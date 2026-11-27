// Command egsconfigcheck reports whether EGS would accept a config file. It
// calls the product's own config.Load and nothing else, so it cannot drift
// from what EGS checks when it starts. A test in scripts/ pins that.
//
// It checks only what config.Load checks: the file's mode, the JSON shape
// (unknown fields refused) and the static rules, among them the signing key
// rules of .docs/system_overview/contracts.md section 3B. Files the config
// names (TLS keys and certificates) are opened by EGS when it starts, not here.
//
// Usage: egsconfigcheck <absolute path to egs.json>
// Exit status: 0 accepted, 1 refused (the reason is on stderr), 2 usage.
package main

import (
	"fmt"
	"os"

	"execution-substrate/egs/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: egsconfigcheck <absolute path to egs.json>")
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "egs config refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("egs config accepted")
}
