package sender

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// sender is the wire: it turns a request into bytes on a socket and back. It sits below every tool
// that sends — the proxy, Repeater, Intruder, the scanner, the crawler, the console and the agent
// surfaces all call it — so it must import none of them (burpsy-react-ui-importbound). A sender that
// imported internal/web would drag the console into every headless tool built on it, and one that
// imported a tool would be a cycle the moment that tool is used where sender already is.
//
// Transitive, not direct: a forbidden package reached through a third one is the same coupling.
// Production imports only (go list -deps without -test). The helper is a copy of
// internal/core/imports_test.go's: core may import nothing of this module, so there is no shared
// package both could use without breaking the rule the core test holds.
var senderForbidden = []string{"web", "scanner", "proxy", "crawler", "intruder", "mcp", "agent"}

func TestSenderImportsNoToolOrSurfacePackage(t *testing.T) {
	module, deps := listDeps(t)
	var bad []string
	reached := map[string]bool{}
	for _, d := range deps {
		reached[d.ImportPath] = true
		for _, f := range senderForbidden {
			if p := module + "/internal/" + f; d.ImportPath == p || strings.HasPrefix(d.ImportPath, p+"/") {
				bad = append(bad, d.ImportPath+" (via "+d.chain()+")")
			}
		}
	}
	if len(bad) != 0 {
		t.Fatalf("internal/sender must import none of internal/{%s}; it reaches:\n  %s",
			strings.Join(senderForbidden, ","), strings.Join(bad, "\n  "))
	}
	// A positive control on the same listing: sender does import core, so a listing that did not show
	// it would be one this check cannot be trusted to have searched.
	if !reached[module+"/internal/core"] {
		t.Fatalf("go list did not show %s/internal/core among sender's dependencies: the listing is incomplete", module)
	}
}

// listedPackage is the part of `go list -deps -json` this test reads, plus the import chain that
// first reached it, for the failure message.
type listedPackage struct {
	ImportPath string
	Standard   bool
	DepOnly    bool
	Imports    []string
	Module     *struct{ Path string }
	via        []string
}

func (p listedPackage) chain() string { return strings.Join(append(p.via, p.ImportPath), " -> ") }

// listDeps runs `go list -deps -json .` in this package's directory and returns the main module's
// path and every non-standard package this package depends on (itself excluded), each with the
// shortest import chain from this package to it.
func listDeps(t *testing.T) (string, []listedPackage) {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-json", ".").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -deps -json: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -deps -json: %v", err)
	}
	byPath := map[string]*listedPackage{}
	var order []string
	var root *listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		byPath[p.ImportPath] = &p
		order = append(order, p.ImportPath)
		if !p.DepOnly {
			root = &p
		}
	}
	// The one package go list was asked about is the one not marked DepOnly.
	if root == nil {
		t.Fatal("go list -deps did not list this package: the check would pass vacuously")
	}
	if root.Module == nil || root.Module.Path == "" {
		t.Fatalf("%s has no module in go list output", root.ImportPath)
	}
	// Breadth-first from the root, so each dependency carries a shortest chain that reaches it.
	seen := map[string]bool{root.ImportPath: true}
	queue := []*listedPackage{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, imp := range p.Imports {
			q, ok := byPath[imp]
			if !ok || seen[imp] {
				continue
			}
			seen[imp] = true
			q.via = append(append([]string(nil), p.via...), p.ImportPath)
			queue = append(queue, q)
		}
	}
	var deps []listedPackage
	for _, path := range order {
		p := byPath[path]
		if p.Standard || p == root {
			continue
		}
		deps = append(deps, *p)
	}
	return root.Module.Path, deps
}
