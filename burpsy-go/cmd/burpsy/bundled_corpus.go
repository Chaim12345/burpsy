package main

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/bcheck/bundled"
	"go.uber.org/zap"
)

// bundledCorpus returns the BCheck corpus compiled into the binary (internal/bcheck/bundled), for
// ActiveScanner.WithBundledCorpus, when no -bchecks directory was given. With one, the operator's
// directory is the corpus and nothing is bundled alongside it.
//
// Attaching it enables nothing: the audit engine dispatches the set only when check_corpus is on,
// and the bundled path, unlike -bchecks, leaves that switch off (burpsy-react-ui-0vzb.21).
//
// An embedded corpus that will not load is a build defect, not an operator error, so it is
// returned as an error and the caller refuses to start rather than run without a set it shipped.
func bundledCorpus(bchecksDir string, logger *zap.Logger) ([]*bcheck.Check, error) {
	if bchecksDir != "" {
		return nil, nil
	}
	m, err := bundled.LoadManifest()
	if err != nil {
		return nil, err
	}
	checks, err := m.EnabledChecks()
	if err != nil {
		return nil, fmt.Errorf("bundled bcheck corpus: %w", err)
	}
	if logger != nil {
		c := m.Counts()
		logger.Info("bundled bcheck corpus available (dispatched only with check_corpus on)",
			zap.String("source", m.Source.Repository+"@"+m.Source.Commit),
			zap.Int("upstream", c.Upstream), zap.Int("imported", c.Imported),
			zap.Int("enabled", c.Enabled), zap.Any("excluded", c.ByCategory))
	}
	return checks, nil
}
