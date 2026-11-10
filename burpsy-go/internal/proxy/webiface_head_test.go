package proxy

import (
	"strings"
	"testing"
)

// A HEAD answer ends at its blank line; the disabled-interface refusal sent its text after it.
func TestDisabledInterfaceAnswerToHEADHasNoBody(t *testing.T) {
	if got := string(webInterfaceDisabledResponse("HEAD")); !strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("HEAD answer carries a body: %q", got)
	}
	if got := string(webInterfaceDisabledResponse("GET")); strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("GET answer lost its body: %q", got)
	}
}
