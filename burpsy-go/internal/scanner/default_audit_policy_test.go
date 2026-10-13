package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// TestDefaultAuditPolicy pins j1mk.37's default audit: the non-destructive active families with
// sound evidence run on a scanner nobody configured, and the intrusive, state-changing and
// out-of-process ones do not. It reads the registry's own gates against the shipped default, so a
// row moving between switches is caught here rather than by a benchmark that silently scores lower.
func TestDefaultAuditPolicy(t *testing.T) {
	cfg := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).ConfigSnapshot()

	on := map[string]bool{
		"CheckActiveInjection":  cfg.CheckActiveInjection,
		"CheckXXE":              cfg.CheckXXE,
		"CheckReflectionProbes": cfg.CheckReflectionProbes,
		"CheckPathTraversal":    cfg.CheckPathTraversal,
	}
	for name, v := range on {
		if !v {
			t.Errorf("%s is off by default; j1mk.37 puts it in the default audit", name)
		}
	}
	off := map[string]bool{
		"CheckExtendedActive":          cfg.CheckExtendedActive,
		"CheckOutOfBand":               cfg.CheckOutOfBand,
		"CheckFileUpload":              cfg.CheckFileUpload,
		"CheckIDOR":                    cfg.CheckIDOR,
		"CheckLoginRateLimit":          cfg.CheckLoginRateLimit,
		"CheckUsernameEnumeration":     cfg.CheckUsernameEnumeration,
		"CheckPasswordReset":           cfg.CheckPasswordReset,
		"CheckSessionManagement":       cfg.CheckSessionManagement,
		"CheckRequestSmuggling":        cfg.CheckRequestSmuggling,
		"CheckInsecureDeserialization": cfg.CheckInsecureDeserialization,
		"CheckSqliHeavyQuery":          cfg.CheckSqliHeavyQuery,
		"CheckSqliOrBoolean":           cfg.CheckSqliOrBoolean,
		"CheckStored":                  cfg.CheckStored,
		"CheckSSRFInBand":              cfg.CheckSSRFInBand,
		"CheckHostHeader":              cfg.CheckHostHeader,
		"CheckGraphQLHardening":        cfg.CheckGraphQLHardening,
		"CheckJwtForgery":              cfg.CheckJwtForgery,
	}
	for name, v := range off {
		if v {
			t.Errorf("%s is on by default; it is intrusive, state-changing or out-of-process and must stay opt-in", name)
		}
	}

	admitted, known := map[string]bool{}, map[string]bool{}
	for _, d := range NativeCheckRegistry() {
		known[d.Name] = true
		if d.Enabled != nil && d.Enabled(&cfg) {
			admitted[d.Name] = true
		}
	}
	for _, row := range []string{
		"OS command injection", "LDAP injection", "XPath injection", "File path manipulation",
		"XML external entity injection", openRedirectIssue, inputReflectionIssue,
	} {
		if !admitted[row] {
			t.Errorf("%q is not admitted by the default configuration", row)
		}
	}
	// The XXE row answers to CheckXXE; its intrusive sibling and the rest of the extended family do not.
	for _, row := range []string{
		"XML entity expansion", "Client-side desync", "Hidden HTTP 2", "TLS certificate",
		"External service interaction (DNS)",
	} {
		if !known[row] {
			t.Errorf("%q is not a registry row; this assertion would pass vacuously", row)
		}
		if admitted[row] {
			t.Errorf("%q is admitted by the default configuration; it belongs to an opt-in family", row)
		}
	}
}
