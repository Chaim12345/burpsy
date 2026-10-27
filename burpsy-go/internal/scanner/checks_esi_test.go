package scanner

import (
	"strings"
	"testing"
)

func TestESIInjectionAgainstTheVulnappTwins(t *testing.T) {
	ct := vulnappTarget(t, &ScanConfig{CheckReflectionProbes: true}, "/esi?tpl=seed", "/safe/esi?tpl=seed")
	if fs := ct.run(t, "/esi?tpl=seed", checkSSIInjection); len(fs) != 1 || !strings.Contains(fs[0].Evidence, "Edge Side Includes") {
		t.Fatalf("/esi: got %v, want one ESI finding", fs)
	}
	if fs := ct.run(t, "/safe/esi?tpl=seed", checkSSIInjection); len(fs) != 0 {
		t.Fatalf("/safe/esi (strips every comment): got %v", fs)
	}
}
