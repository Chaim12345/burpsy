package domexec

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsErrorStatusPage(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		// chromedp.Navigate's wording, wrapped the way ObserveTaint wraps it.
		{fmt.Errorf("domexec: observe taint at %q: %w", "http://h/x", errors.New("page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE")), true},
		// page.Navigate's errorText, as the referrer branch reports it.
		{errors.New(`navigation to "http://h/x" failed: net::ERR_HTTP_RESPONSE_CODE_FAILURE`), true},
		// A target that could not be reached is a real failure.
		{errors.New("page load error net::ERR_CONNECTION_REFUSED"), false},
		{errors.New("page load error net::ERR_INVALID_RESPONSE"), false},
		{errors.New("context deadline exceeded"), false},
	} {
		if got := IsErrorStatusPage(c.err); got != c.want {
			t.Errorf("IsErrorStatusPage(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
