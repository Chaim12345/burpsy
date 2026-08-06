package advisory

import "testing"

func TestBundledCatalogueLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Len() != 183 {
		t.Errorf("Len = %d, want 183", c.Len())
	}
	d, ok := c.ByName("SQL injection")
	if !ok {
		t.Fatal("SQL injection not found by name")
	}
	if d.Severity != SeverityHigh {
		t.Errorf("severity = %q, want HIGH", d.Severity)
	}
	if d.HexIndex() != "00100200" {
		t.Errorf("hex = %q, want 00100200", d.HexIndex())
	}
	if len(d.Classification) == 0 {
		t.Error("expected CWE/CAPEC classifications")
	}
	if _, ok := c.ByIndex(d.TypeIndex); !ok {
		t.Error("index lookup failed")
	}
	if _, ok := c.ByName("  sql   INJECTION!! "); !ok {
		t.Error("normalisation failed")
	}
}
