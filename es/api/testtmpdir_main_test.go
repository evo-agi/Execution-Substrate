package api

import (
	"os"
	"testing"

	"execution-substrate/internal/testtmpdir"
)

// TestMain runs the tests of this package under a temporary directory whose
// path holds no symbolic link. See package testtmpdir.
func TestMain(m *testing.M) { os.Exit(testtmpdir.Main(m)) }
