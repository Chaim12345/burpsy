package scanner

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// vhosts serves an admin application for Host: admin*, a "no such site" page for unknown names and
// the shop for everything else; flat serves one page whatever the Host.
func vhosts(flat bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case flat:
			_, _ = w.Write([]byte("<h1>Shop</h1><p>catalogue</p>"))
		case strings.HasPrefix(r.Host, "admin"):
			_, _ = w.Write([]byte("<h1>Admin console</h1><form>users, billing, keys</form><table>" + strings.Repeat("<tr><td>row</td></tr>", 30) + "</table>"))
		case strings.HasSuffix(strings.Split(r.Host, ":")[0], ".invalid"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("no such site"))
		default:
			_, _ = w.Write([]byte("<h1>Shop</h1><p>catalogue</p>"))
		}
	}
}

func TestAnInternalHostNameThatSelectsAnotherAppIsReported(t *testing.T) {
	ct := newCheckTarget(t, vhosts(false), &ScanConfig{CheckHostHeader: true}, vulnapp.Endpoint{Path: "/"})
	fs := ct.run(t, "/", checkHostHeaderInjection)
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "Host: admin") {
		t.Fatalf("want one finding naming Host: admin, got %d: %v", len(fs), fs)
	}
	flat := newCheckTarget(t, vhosts(true), &ScanConfig{CheckHostHeader: true}, vulnapp.Endpoint{Path: "/"})
	if fs := flat.run(t, "/", checkHostHeaderInjection); len(fs) != 0 {
		t.Errorf("a server that ignores Host was reported: %s", fs[0].Evidence)
	}
}
