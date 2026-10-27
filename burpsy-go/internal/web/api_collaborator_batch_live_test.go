//go:build oob_live

// The batch mint against the REAL public interactsh pool, behind the oob_live build tag like
// internal/oob's own live test: a per-PR gate whose result depends on a third-party service being
// reachable is a flaky gate, and this one used to turn "the pool was down" into a green skip
// (bead burpsy-react-ui-interactsh-public). The default suite proves the same contract hermetically
// (TestTheCollaboratorBatchMintSharesOneRegistration); this run proves the real binary, a real
// registration and a real announced domain satisfy it too. Run it deliberately:
//
//	go test -tags oob_live ./internal/web/ -run PublicPool -count=1 -v
//
// Asked for explicitly, a missing binary or an unreachable pool is a failure, not a skip.
package web

import (
	"os/exec"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

func TestTheCollaboratorBatchMintAgainstThePublicPool(t *testing.T) {
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		t.Fatalf("-tags oob_live asks for the live registration, and interactsh-client is not on PATH: %v", err)
	}
	// Real registration via the real binary and the real public pool (empty ServerURL = the
	// client's own default pool). The 45s bound covers the slow end of a real DNS round trip.
	provider := scanner.NewLazyOOBProvider(oob.Options{Timeout: 45 * time.Second})
	t.Cleanup(func() { _ = provider.Close() })

	s := newTestServerWithScanner(t)
	s.wiredScanner().WithOOBProvider(provider)
	t.Logf("registered domain: %s", assertBatchMint(t, s))
}
