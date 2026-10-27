package web

import (
	"os"
	"testing"

	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

// TestMain applies the browser capability ledger: a test here that skipped because no browser could
// be launched fails the package unless BURPSY_ALLOW_NO_CHROME=1 (see internal/domexec/domexectest).
func TestMain(m *testing.M) {
	os.Exit(domexectest.Main(m))
}
