// Conformance runner for the Go bcheck parser, mirroring crates/bcheck/src/bin/conform.rs
// so both parsers are measured over the identical corpus.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

func main() {
	root := "/tmp/BChecks"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var files []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && filepath.Ext(p) == ".bcheck" {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)

	ok, fail := 0, 0
	var failures []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		_, perr := bcheck.Parse(string(src))
		if perr != nil {
			fail++
			failures = append(failures, fmt.Sprintf("%s: %v", f, perr))
		} else {
			ok++
		}
	}

	fmt.Printf("files          : %d\n", len(files))
	fmt.Printf("parsed OK      : %d\n", ok)
	fmt.Printf("failed         : %d\n", fail)
	if len(files) > 0 {
		fmt.Printf("accept rate    : %.1f%%\n", float64(ok)*100.0/float64(len(files)))
	}
	fmt.Printf("\nfirst 25 failures:\n")
	for i, f := range failures {
		if i >= 25 {
			break
		}
		fmt.Printf("  %s\n", f)
	}
}
