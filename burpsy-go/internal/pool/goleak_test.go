package pool

import (
	"testing"

	"go.uber.org/goleak"
)

// burpsy-react-ui-u5jf: every test in this package runs under a goroutine-leak
// check at package exit (hygiene gate, per the u5jf scoping: no speed claim).
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
