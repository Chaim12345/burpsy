package main

import (
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// bundledCorpus returns the BCheck corpus compiled into the binary; a -bchecks directory
// adds to it rather than replacing it (scanner.BundledCorpus). It delegates to the shared
// helper because the desktop binary loads the same corpus through it, and two copies would
// drift into two different answers about which checks the binary carries. See
// internal/scanner/wiring.go.
func bundledCorpus(logger *zap.Logger) ([]*bcheck.Check, error) {
	return scanner.BundledCorpus(logger)
}
