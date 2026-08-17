// Command _rows prints each check family's catalog rows, so a manifest author has exact names.
package main

import (
	"fmt"
	"sort"

	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func main() {
	families := map[string][]scanner.CheckDescriptor{
		"posture":    scanner.PassivePostureCheckDescriptors(),
		"analysis":   scanner.PassiveAnalysisCheckDescriptors(),
		"headers":    scanner.HeaderCheckDescriptors(),
		"cache":      scanner.CacheCheckDescriptors(),
		"reflection": scanner.ReflectionProbeCheckDescriptors(),
		"respdep":    scanner.ResponseDependenceCheckDescriptors(),
		"discovery":  scanner.HostDiscoveryCheckDescriptors(),
		"dom":        scanner.DOMCheckDescriptors(),
		"domextra":   scanner.DOMExtraCheckDescriptors(),
		"remaining":  scanner.RemainingCheckDescriptors(),
		"final":      scanner.FinalCheckDescriptors(),
		"stored":     scanner.StoredCheckDescriptors(),
		"injection":  scanner.InjectionCheckDescriptors(),
	}

	done := map[string]bool{}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !e.Safe {
			done[e.Row] = true
		}
	}

	names := make([]string, 0, len(families))
	for k := range families {
		names = append(names, k)
	}
	sort.Strings(names)

	total, demonstrated := 0, 0
	for _, fam := range names {
		ds := families[fam]
		fmt.Printf("\n=== %s (%d rows) ===\n", fam, len(ds))
		rows := make([]string, 0, len(ds))
		for _, d := range ds {
			rows = append(rows, d.Name)
		}
		sort.Strings(rows)
		for _, r := range rows {
			total++
			mark := " "
			if done[r] {
				mark = "x"
				demonstrated++
			}
			fmt.Printf("  [%s] %s\n", mark, r)
		}
	}
	fmt.Printf("\ntotal=%d demonstrated=%d remaining=%d\n", total, demonstrated, total-demonstrated)
}
