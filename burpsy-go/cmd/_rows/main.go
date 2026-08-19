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

	// Rows nobody can ever demonstrate. Counting them as remaining work inflates the number by four
	// jobs that do not exist; they are marked "-" and reported on their own line instead. The list
	// and its reasons come from the scanner package, so this command cannot exempt a row the code
	// does not agree is exempt.
	exempt := scanner.UndemonstrableRows()

	names := make([]string, 0, len(families))
	for k := range families {
		names = append(names, k)
	}
	sort.Strings(names)

	total, demonstrated, exempted := 0, 0, 0
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
			switch {
			case done[r]:
				mark = "x"
				demonstrated++
			case exempt[r] != "":
				mark = "-"
				exempted++
			}
			fmt.Printf("  [%s] %s\n", mark, r)
		}
	}
	fmt.Printf("\ntotal=%d demonstrated=%d exempt=%d remaining=%d\n",
		total, demonstrated, exempted, total-demonstrated-exempted)

	if exempted > 0 {
		fmt.Printf("\npermanently exempt (not outstanding work):\n")
		rows := make([]string, 0, len(exempt))
		for r := range exempt {
			rows = append(rows, r)
		}
		sort.Strings(rows)
		for _, r := range rows {
			fmt.Printf("  [-] %s\n      %s\n", r, exempt[r])
		}
	}
}
