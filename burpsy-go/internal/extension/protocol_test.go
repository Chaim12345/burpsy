package extension

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// MethodSpecs is what the APIs tab renders, so it has to be checked against the dispatcher rather than
// maintained next to it.
//
// The technique is internal/web/route_manifest_test.go's, and it exists for the same reason: prose
// about a wire protocol drifts, and the drift is invisible until someone writes a plugin against the
// documentation and it does not work. So the host-to-plugin half is read out of the string literals
// passed to session.call, and the plugin-to-host half out of the keys of the `inbound` table.
//
// What this cannot check is whether the *shapes* in Params and Result are right. That is what
// Test_each_registration_kind_invokes_its_documented_method does, by driving a real plugin.
func documentedAndDispatched(t *testing.T) (called []string, inboundMethods []string) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", notATestFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse this package: %v", err)
	}
	pkg, ok := pkgs["extension"]
	if !ok {
		t.Fatal("no package named extension in this directory; the AST walk is broken, not the protocol")
	}

	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			// Every call site is `<session>.call(ctx, "method", …)`, with the method as a literal. That is
			// a constraint the package doc states rather than a coincidence: a name built from a variable
			// would be invisible here, and Test_every_method_name_is_a_literal fails if one appears.
			if call, isCall := n.(*ast.CallExpr); isCall {
				if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "call" && len(call.Args) >= 2 {
					if name, ok := stringLiteral(call.Args[1]); ok {
						called = append(called, name)
					}
				}
			}
			// The inbound table's keys are the methods a plugin may send.
			spec, isSpec := n.(*ast.ValueSpec)
			if !isSpec || len(spec.Names) == 0 || spec.Names[0].Name != "inbound" || len(spec.Values) == 0 {
				return true
			}
			composite, isComposite := spec.Values[0].(*ast.CompositeLit)
			if !isComposite {
				return true
			}
			for _, element := range composite.Elts {
				kv, isKV := element.(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				if name, ok := stringLiteral(kv.Key); ok {
					inboundMethods = append(inboundMethods, name)
				}
			}
			return true
		})
	}
	return dedup(called), dedup(inboundMethods)
}

// notATestFile keeps the walk on the shipped source. Including _test.go would let a method name
// invented by a test satisfy the check that the documented set is the dispatched one.
func notATestFile(info fs.FileInfo) bool {
	return !strings.HasSuffix(info.Name(), "_test.go")
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func documented(direction Direction) []string {
	out := make([]string, 0, len(MethodSpecs))
	for _, spec := range MethodSpecs {
		if spec.Direction == direction {
			out = append(out, spec.Name)
		}
	}
	sort.Strings(out)
	return out
}

func Test_the_documented_method_set_is_the_dispatched_method_set(t *testing.T) {
	called, inboundMethods := documentedAndDispatched(t)
	if len(called) == 0 || len(inboundMethods) == 0 {
		t.Fatalf("parsed %d outbound and %d inbound method(s); the AST walk is broken, not the protocol",
			len(called), len(inboundMethods))
	}

	compare := func(what string, dispatched, docs []string) {
		if strings.Join(dispatched, " ") == strings.Join(docs, " ") {
			return
		}
		t.Errorf("the %s methods this package dispatches are\n  %v\nand MethodSpecs documents\n  %v\n"+
			"MethodSpecs is what the APIs tab serves, so a difference here is a plugin author being told "+
			"about a method that does not exist, or not being told about one that does.", what, dispatched, docs)
	}
	compare("host-to-plugin", called, documented(HostToPlugin))
	compare("plugin-to-host", inboundMethods, documented(PluginToHost))
}

// A method name built from a variable would be invisible to the check above, so it is refused rather
// than silently uncovered.
func Test_every_dispatched_method_name_is_a_literal(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", notATestFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse this package: %v", err)
	}
	nonLiteral := 0
	for _, file := range pkgs["extension"].Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			sel, isSel := call.Fun.(*ast.SelectorExpr)
			if !isSel || sel.Sel.Name != "call" || len(call.Args) < 2 {
				return true
			}
			if _, ok := stringLiteral(call.Args[1]); !ok {
				nonLiteral++
			}
			return true
		})
	}
	if nonLiteral > 0 {
		t.Errorf("%d call(s) name their method with something other than a string literal; MethodSpecs "+
			"cannot be checked against those", nonLiteral)
	}
}

// Every invocation method names the registration kind it serves, and every kind the host accepts has
// one. A kind admitted by validKinds with no method behind it would be a registration an operator can
// see and nothing can invoke.
func Test_every_registration_kind_has_exactly_one_invocation_method(t *testing.T) {
	byKind := map[Kind][]string{}
	for _, spec := range MethodSpecs {
		if spec.Kind == "" {
			continue
		}
		byKind[spec.Kind] = append(byKind[spec.Kind], spec.Name)
	}
	for kind := range validKinds {
		switch methods := byKind[kind]; len(methods) {
		case 1:
		case 0:
			t.Errorf("kind %q is accepted at load and no documented method invokes it", kind)
		default:
			t.Errorf("kind %q is invoked by %v; Invoke dispatches one method per kind", kind, methods)
		}
	}
	for kind := range byKind {
		if !validKinds[kind] {
			t.Errorf("method for kind %q, which validKinds refuses at load", kind)
		}
	}
	// Three, and stated as a number: the ten Montoya registration points that hand Burp a Swing object
	// are deliberately absent, and a fourth appearing here should be a decision rather than a diff.
	if len(validKinds) != 3 {
		t.Errorf("this host accepts %d registration kinds, and the three with an honest web analogue "+
			"are context-menu, menu and editor-tab. Adding a fourth means deciding what it renders as.",
			len(validKinds))
	}
}

// Every documented method says what it is for, and the API view is generated from the same table
// rather than restating it.
func Test_the_api_view_is_generated_from_the_method_table(t *testing.T) {
	view := API()
	if len(view.Methods) != len(MethodSpecs) {
		t.Errorf("API() serves %d method(s) against %d documented", len(view.Methods), len(MethodSpecs))
	}
	if view.ProtocolVersion != ProtocolVersion {
		t.Errorf("API() reports protocol %d, want %d", view.ProtocolVersion, ProtocolVersion)
	}
	for _, spec := range view.Methods {
		if spec.Why == "" || spec.Params == "" || spec.Result == "" {
			t.Errorf("method %q is documented without one of params, result or reason", spec.Name)
		}
		switch spec.Call {
		case "request", "notification":
		default:
			t.Errorf("method %q has call style %q, which is neither a request nor a notification",
				spec.Name, spec.Call)
		}
	}
	if len(view.Kinds) != len(validKinds) {
		t.Errorf("API() lists %d kind(s) against %d accepted", len(view.Kinds), len(validKinds))
	}
	for _, kind := range view.Kinds {
		if kind.Label == "" || kind.Montoya == "" || kind.Method == "" {
			t.Errorf("kind %q is served without a label, a method or the Montoya call it stands in for",
				kind.Kind)
		}
	}
	// The absences are part of the contract. An operator reading this tab must be told that there is no
	// store and that a plugin cannot originate a request, rather than inferring both from silence.
	if len(view.Unsupported) == 0 {
		t.Fatal("API() states nothing as unsupported, so every absence is left to be inferred")
	}
	joined := strings.ToLower(strings.Join(func() []string {
		out := make([]string, 0, len(view.Unsupported))
		for _, item := range view.Unsupported {
			out = append(out, item.What+" "+item.Why)
		}
		return out
	}(), " | "))
	for _, want := range []string{"registry", "component", "authorisedsender", "caret"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the unsupported list does not mention %q", want)
		}
	}
}
