package main

import (
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// bundledCorpus returns the BCheck corpus compiled into the binary when no -bchecks directory
// was given. It delegates to scanner.BundledCorpusForDir: the desktop binary loads the same
// corpus through the same helper, and two copies would drift into two different answers about
// which checks the binary carries. See internal/scanner/wiring.go.
func bundledCorpus(bchecksDir string, logger *zap.Logger) ([]*bcheck.Check, error) {
	return scanner.BundledCorpusForDir(bchecksDir, logger)
}
