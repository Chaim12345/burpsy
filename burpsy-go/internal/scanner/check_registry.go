package scanner

import (
	"context"
	"fmt"
	"sort"

	"github.com/burpsy-go/burpsy/internal/core"
)

// NativeCheckRegistry returns the checks currently implemented as Go evaluators.
// The catalog remains the source of issue metadata; this registry only declares
func NativeCheckRegistry() []CheckDescriptor {
	// The three original rows now live in checks_core_injection.go, driven through enumerated
	// insertion points. They used to be inline closures over scanner.go helpers that appended a
	// parameter with a guessed name; see that file's header for what that cost.
	out := coreInjectionDescriptors()
	out = append(out,
		nativeDescriptor("JWT weak HMAC secret", DispatchScopePerRequest, func(c *ScanConfig) bool { return c != nil && c.CheckJwtWeak }, func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
			return cc.Scanner.checkJWTWeak(ctx, cc.Exchange), nil
		}),
		nativeDescriptor("Vulnerable JavaScript dependency", DispatchScopePerRequest, func(c *ScanConfig) bool { return c != nil && c.CheckJSVulns }, func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
			return cc.Scanner.checkJSVulns(ctx, cc.Exchange), nil
		}),
	)
	// Task 6 slices: each contributor claims a disjoint set of catalog TypeIndex
	// values (see docs/SCANNER-COVERAGE.md for the accounting). Aggregated here
	// rather than inline above so each slice's own file stays the single place
	// its checks are defined and tested.
	out = append(out, HeaderCheckDescriptors()...)
	out = append(out, CacheCheckDescriptors()...)
	out = append(out, DOMAndStoredXSSDescriptors()...)
	out = append(out, DeclinedCatalogDescriptors()...)
	out = append(out, ReflectionProbeCheckDescriptors()...)
	out = append(out, HostDiscoveryCheckDescriptors()...)
	out = append(out, ResponseDependenceCheckDescriptors()...)
	out = append(out, PassivePostureCheckDescriptors()...)
	out = append(out, PassiveAnalysisCheckDescriptors()...)
	out = append(out, InjectionCheckDescriptors()...)
	out = append(out, DOMCheckDescriptors()...)
	out = append(out, RemainingCheckDescriptors()...)
	out = append(out, DOMExtraCheckDescriptors()...)
	out = append(out, StoredCheckDescriptors()...)
	out = append(out, FinalCheckDescriptors()...)
	return out
}

func nativeDescriptor(name string, scope DispatchScope, enabled func(*ScanConfig) bool, run CheckRunner) CheckDescriptor {
	issue, ok := ByName(name)
	if !ok {
		panic(fmt.Sprintf("native scanner issue %q is absent from catalog", name))
	}
	return CheckDescriptor{
		TypeIndex:      issue.TypeIndex,
		Name:           issue.Name,
		Implementation: ImplementationNative,
		Phase:          PhaseActive,
		Scope:          scope,
		Enabled:        enabled,
		Run:            run,
	}
}

func declinedDescriptor(name string, scope DispatchScope, enabled func(*ScanConfig) bool, reason string) CheckDescriptor {
	issue, ok := ByName(name)
	if !ok {
		panic(fmt.Sprintf("declined scanner issue %q is absent from catalog", name))
	}
	return CheckDescriptor{
		TypeIndex:      issue.TypeIndex,
		Name:           issue.Name,
		Implementation: ImplementationDeclined,
		Phase:          PhaseActive,
		Scope:          scope,
		Enabled:        enabled,
		DeclineReason:  reason,
	}
}

// nativeActiveCheckSet adapts the typed registry to the existing audit ledger.
// Keeping this adapter narrow lets the ledger remain stable while check logic
// migrates from the old table to descriptors.
func nativeActiveCheckSet() []activeCheck {
	descriptors := NativeCheckRegistry()
	out := make([]activeCheck, 0, len(descriptors))
	for _, descriptor := range descriptors {
		d := descriptor
		var run func(*ActiveScanner, context.Context, *core.Exchange) ([]*Finding, error)
		if d.Run != nil {
			run = wrapDescriptor(d)
		}
		out = append(out, activeCheck{
			name:    d.Name,
			scope:   d.Scope,
			enabled: d.Enabled,
			run:     run,
		})
	}
	return out
}

// wrapDescriptor builds the run wrapper for one descriptor, which is exactly the path the audit
// engine uses to turn a CheckDescriptor into a dispatched check. For a stored-per-insertion-point
// (second-order) descriptor it resolves the prior same-endpoint exchange from the store and threads
// it into CheckContext.StoredExchange; every other scope receives nil, unchanged. Split out of
// nativeActiveCheckSet so the scanner's own tests can exercise the threading with a synthetic
// descriptor instead of un-declining a catalog issue.
func wrapDescriptor(d CheckDescriptor) func(*ActiveScanner, context.Context, *core.Exchange) ([]*Finding, error) {
	return func(s *ActiveScanner, ctx context.Context, exchange *core.Exchange) ([]*Finding, error) {
		var stored *core.Exchange
		if d.Scope == DispatchScopeStoredPerInsertionPoint && s != nil && s.store != nil && exchange != nil {
			stored, _ = s.store.PriorExchange(exchange.Host, exchange.Port, exchange.TLS, exchange.Path, exchange.ID)
		}
		return d.Run(ctx, newCheckContextForRun(ctx, s, exchange, stored))
	}
}

// ValidateRegistry catches omissions and malformed rows before dispatch. It is
// intentionally independent of a live scanner so generators and CI can call it.
func ValidateRegistry(registry []CheckDescriptor) error {
	seen := make(map[uint32]struct{}, len(registry))
	for _, descriptor := range registry {
		if !descriptor.Valid() {
			return fmt.Errorf("invalid scanner descriptor %q (%d)", descriptor.Name, descriptor.TypeIndex)
		}
		if _, exists := seen[descriptor.TypeIndex]; exists {
			return fmt.Errorf("duplicate scanner TypeIndex %d", descriptor.TypeIndex)
		}
		if _, ok := ByTypeIndex(descriptor.TypeIndex); !ok {
			return fmt.Errorf("scanner TypeIndex %d is absent from catalog", descriptor.TypeIndex)
		}
		seen[descriptor.TypeIndex] = struct{}{}
	}
	return nil
}

// RegistryByTypeIndex returns a stable, binary-searchable view for dispatch and
// coverage reporting.
func RegistryByTypeIndex(registry []CheckDescriptor) ([]CheckDescriptor, error) {
	if err := ValidateRegistry(registry); err != nil {
		return nil, err
	}
	out := append([]CheckDescriptor(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].TypeIndex < out[j].TypeIndex })
	return out, nil
}
