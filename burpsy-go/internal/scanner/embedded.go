package scanner

import (
	"embed"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// bchecks holds PortSwigger's published BCheck corpus (264 files, Apache-2.0,
// LICENSE bundled alongside) so passive scanning works out of the box. The
// corpus is an oracle, not a fixture: every file parses and the passive count
// is pinned by TestEmbeddedCorpusParsesCleanly so a corpus update cannot drift
// silently from what the proxy actually runs.
//
//go:embed bchecks
var embeddedCorpus embed.FS

// LoadEmbedded returns a PassiveScanner running the bundled PortSwigger BCheck
// corpus. It is the default when --bchecks is not given: passive scanning is
// on, not opt-in.
func LoadEmbedded(store *core.TrafficStore, scope *core.Scope, logger *zap.Logger) (*PassiveScanner, error) {
	return LoadFS(embeddedCorpus, store, scope, logger)
}
