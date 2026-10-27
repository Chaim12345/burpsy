package sender

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Files allowed to build a raw dialer or transport. A new entry needs a reason it cannot route
// through the sender's dial path (scope, upstream proxy, carrier, resolution override).
var rawDialAllowed = map[string]string{
	"internal/sender/network.go":                     "the dial path itself",
	"internal/sender/sender.go":                      "the dial path itself",
	"internal/upstream/upstream.go":                  "the upstream proxy dialers",
	"internal/upstream/carrier.go":                   "the SOCKS carrier",
	"internal/upstream/upstreamtest/upstreamtest.go": "test fixture",
	"internal/alpn/alpn.go":                          "takes the carrier and resolver from the caller",
	"internal/alpn/fingerprint.go":                   "takes the carrier and resolver from the caller",
	"internal/httputil/h3.go":                        "dial hook installed by the caller",
	"internal/egressgate/egressgate.go":              "the subprocess egress gate",
	"internal/web/api_collaborator_health.go":        "operator-configured collaborator, not the target",
	"internal/scanner/checks_pwreset.go":             "operator-configured mailbox, not the target",
	"internal/vulnapp/vulnapp_ssrf.go":               "the intentionally vulnerable test app",
}

var rawDialCalls = map[string]bool{"net.Dial": true, "net.DialTimeout": true, "tls.Dial": true, "tls.DialWithDialer": true}
var rawDialTypes = map[string]bool{"http.Transport": true, "http3.Transport": true, "net.Dialer": true, "tls.Dialer": true}

func TestNoRawDialsOutsideTheDialPath(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "cmd/") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var name string
			switch x := n.(type) {
			case *ast.CallExpr:
				if s := selName(x.Fun); rawDialCalls[s] {
					name = s
				}
			case *ast.CompositeLit:
				if s := selName(x.Type); rawDialTypes[s] {
					name = s
				}
			}
			if name != "" {
				if _, ok := rawDialAllowed[rel]; !ok {
					t.Errorf("%s: %s outside the dial path", fset.Position(n.Pos()), name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func selName(e ast.Expr) string {
	if s, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := s.X.(*ast.Ident); ok {
			return id.Name + "." + s.Sel.Name
		}
	}
	return ""
}
