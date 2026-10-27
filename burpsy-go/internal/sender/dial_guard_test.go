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
	"cmd/live-test/main.go":                          "dev harness against a local target",
	"cmd/xsschallenge/main.go":                       "dev harness against a local challenge server",
}

var rawDialCalls = map[string]bool{"net.Dial": true, "net.DialTimeout": true, "tls.Dial": true, "tls.DialWithDialer": true,
	"http.Get": true, "http.Head": true, "http.Post": true, "http.PostForm": true}
var rawDialVars = map[string]bool{"http.DefaultClient": true, "http.DefaultTransport": true}
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
		pkgs := importNames(f)
		ast.Inspect(f, func(n ast.Node) bool {
			var name string
			switch x := n.(type) {
			case *ast.CallExpr:
				if s := selName(pkgs, x.Fun); rawDialCalls[s] {
					name = s
				} else if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 && rawDialTypes[selName(pkgs, x.Args[0])] {
					name = selName(pkgs, x.Args[0])
				}
			case *ast.CompositeLit:
				if s := selName(pkgs, x.Type); rawDialTypes[s] {
					name = s
				}
			case *ast.ValueSpec:
				if s := selName(pkgs, x.Type); rawDialTypes[s] {
					name = s
				}
			case *ast.SelectorExpr:
				if s := selName(pkgs, x); rawDialVars[s] {
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

// importNames maps each import's local name to its package's last path element, so an alias
// (stdhttp "net/http") still reads as http.
func importNames(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		p := strings.Trim(im.Path.Value, `"`)
		base := p[strings.LastIndex(p, "/")+1:]
		local := base
		if im.Name != nil {
			local = im.Name.Name
		}
		switch p {
		case "net", "crypto/tls", "net/http", "github.com/quic-go/quic-go/http3":
			out[local] = base
		}
	}
	return out
}

func selName(pkgs map[string]string, e ast.Expr) string {
	if s, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := s.X.(*ast.Ident); ok {
			if base, ok := pkgs[id.Name]; ok {
				return base + "." + s.Sel.Name
			}
		}
	}
	return ""
}
