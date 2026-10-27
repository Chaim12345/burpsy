package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// core is the bottom of the dependency graph: the message, scope and finding types every other
// package is built on. It imports no burpsy package, and this test is what keeps it so
// (burpsy-react-ui-importbound). A core that imported, say, internal/web would make every package
// that needs a request type depend on the console, and the first import cycle would be the first
// anyone heard of it.
//
// Transitive, not direct: a forbidden package reached through a third one is the same coupling.
// Production imports only (go list -deps without -test); a test helper is not a dependency of the
// shipped binary.
func TestCoreImportsNoBurpsyPackage(t *testing.T) {
	module, deps := listDeps(t)
	var bad []string
	for _, d := range deps {
		if strings.HasPrefix(d.ImportPath, module+"/") {
			bad = append(bad, d.ImportPath+" (via "+d.chain()+")")
		}
	}
	if len(bad) != 0 {
		t.Fatalf("internal/core must import no package of this module; it reaches:\n  %s", strings.Join(bad, "\n  "))
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
