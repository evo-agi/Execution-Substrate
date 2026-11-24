// Command esconfigcheck reports whether ES would accept a config file. It
// calls the product's own config.Load and nothing else, so it cannot drift
// from what ES checks when it starts. A test in scripts/ pins that.
//
// It checks only what config.Load checks: the JSON shape (unknown fields
// refused) and the static rules. Files the config names (keys, tokens,
// certificates) are opened by ES when it starts, not here.
//
// Usage: esconfigcheck <absolute path to es.json>
// Exit status: 0 accepted, 1 refused (the reason is on stderr), 2 usage.
package main

import (
	"fmt"
	"os"

	"execution-substrate/es/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: esconfigcheck <absolute path to es.json>")
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "es config refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("es config accepted")
}
