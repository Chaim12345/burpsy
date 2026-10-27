// AST taint pass on goja/parser (r996): the analysis dom.go's header says a missing dependency
// forbade. The dependency has been linked since 950b6a4d, so the lexical pass's three known losses
// a real grammar recovers are recovered here:
//
//   - function arguments: a call `set(location.hash)` binds the callee's parameter, and the sink
//     inside the callee body is traced (the lexical pass left the parameter untraced);
//   - property aliases: `o.v = location.hash` taints o.v (the lexer tracked plain identifiers
//     only);
//   - statement splitting itself: no regex-literal heuristic, no merge-forward guesswork, and a
//     template literal's `${...}` substitutions are expressions read for taint.
//
// What deliberately does NOT change: the three-outcome discipline, the budget accounting (the
// propagation phase is capped at half the statement budget, exactly like the lexical pass), the
// fixpoint's order-insensitivity (a sink textually above the assignment that taints its input is
// still reported - clearing taint on reassignment is a behaviour change beyond this bead), and
// every table in dom_data.go. A script goja cannot parse falls back to the lexical pass rather
// than going blind.
//
// The phase structure mirrors the lexical pass: a propagation fixpoint over a FLAT taint table
// (assignments inside function bodies bind into the same table, as the lexer's text scan saw
// them), then one sink pass. The sink pass is where scopes appear: a call to a known function
// re-enters the callee with its parameters bound to the argument taints, and event-handler
// function literals passed to calls are walked with the enclosing table visible.
package scanner

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
)

// domASTFunc is a function the walker can re-enter at a call site: its parameter names and body.
type domASTFunc struct {
	params []string
	body   *ast.BlockStatement
}

// domASTScope is one call frame's taint table; lookups walk the parent chain so a callee sees the
// flat global table underneath its parameter bindings.
type domASTScope struct {
	parent *domASTScope
	taint  map[string]domTaint
	order  []string
}

func (s *domASTScope) lookup(name string) (domTaint, bool) {
	for sc := s; sc != nil; sc = sc.parent {
		if t, ok := sc.taint[name]; ok {
			return t, true
		}
	}
	return domTaint{}, false
}

// bind records taint, first-write-wins (the lexical propagate's rule), and reports whether the
// name was newly tainted - the signal the fixpoint loop counts.
func (s *domASTScope) bind(name string, t domTaint) bool {
	if s.taint == nil {
		s.taint = map[string]domTaint{}
	}
	if _, ok := s.taint[name]; ok {
		return false
	}
	s.taint[name] = t
	s.order = append(s.order, name)
	return true
}

// domASTWalker carries the walk's state. It borrows the owning engine's budget, result and seen
// set so a finding reached through the AST is indistinguishable from one reached lexically.
type domASTWalker struct {
	e     *domEngine
	fset  *file.FileSet
	src   string
	funcs map[string]domASTFunc
	// flat is the propagation phase's single taint table (the lexical pass's e.taint analogue).
	flat *domASTScope
	// sinksOn switches sink decisions on: the propagation phase binds only, the sink pass decides.
	sinksOn bool
	// depth and visiting bound re-entrant callee walks: a recursive script cannot spin the pass.
	depth    int
	visiting map[string]bool
	// scopes keeps one child scope per function value or call site across propagation rounds: a
	// fresh scope each round re-bound the body's locals as new every round, so the fixpoint never
	// reached zero and every handler with a local spent all the rounds.
	scopes map[ast.Node]*domASTScope
}

// childScope is node's scope under parent, the same one every round.
func (w *domASTWalker) childScope(node ast.Node, parent *domASTScope) *domASTScope {
	if w.scopes == nil {
		w.scopes = map[ast.Node]*domASTScope{}
	}
	s, ok := w.scopes[node]
	if !ok {
		s = &domASTScope{}
		w.scopes[node] = s
	}
	s.parent = parent
	return s
}

const domASTMaxCallDepth = 4

// analyseAST parses one script and walks it. ok is false when goja cannot parse the source: the
// caller then runs the lexical path instead.
func (e *domEngine) analyseAST(sc domScriptSrc) (ok bool) {
	fset := &file.FileSet{}
	prog, err := parser.ParseFile(fset, "", sc.text, 0)
	if err != nil {
		return false
	}
	w := &domASTWalker{
		e: e, fset: fset, src: sc.text,
		funcs: map[string]domASTFunc{}, flat: &domASTScope{}, visiting: map[string]bool{},
	}
	w.hoist(prog.Body)

	// Propagation fixpoint, capped at half the statement budget - the reserve that guarantees a
	// phase cut short still leaves the sink pass its share, as in the lexical pass.
	propCap := e.budget.MaxStatements / 2
	if propCap < 1 {
		propCap = 1
	}
	propSpent := 0
	for round := 1; round <= e.budget.MaxPropagationRounds; round++ {
		e.res.Budget.Rounds = round
		added := 0
		for _, st := range prog.Body {
			if propSpent >= propCap {
				e.res.Budget.record(DOMStopStatements)
				goto sinks
			}
			if !e.spend(1) {
				goto sinks
			}
			propSpent++
			added += w.walkStatement(st, sc, w.flat)
		}
		if added == 0 {
			break
		}
		if round == e.budget.MaxPropagationRounds {
			// Still discovering taint with no rounds left: the chain continues past here.
			e.res.Budget.record(DOMStopPropagationRounds)
		}
	}

sinks:
	w.sinksOn = true
	for _, st := range prog.Body {
		if !e.spend(1) {
			return true
		}
		w.walkStatement(st, sc, w.flat)
	}
	return true
}

// hoist registers every function declared or assigned at the top level, so a call above its
// function's declaration resolves - hoisting is the language's rule and the lexical pass's
// effective behaviour.
func (w *domASTWalker) hoist(stmts []ast.Statement) {
	for _, st := range stmts {
		switch s := st.(type) {
		case *ast.FunctionDeclaration:
			w.registerFunc(s.Function)
		case *ast.VariableStatement:
			w.hoistBindings(s.List)
		case *ast.LexicalDeclaration:
			w.hoistBindings(s.List)
		}
	}
}

func (w *domASTWalker) hoistBindings(list []*ast.Binding) {
	for _, b := range list {
		if b == nil {
			continue
		}
		id, ok := b.Target.(*ast.Identifier)
		if !ok {
			continue
		}
		if fl, isFn := b.Initializer.(*ast.FunctionLiteral); isFn {
			w.funcs[id.Name.String()] = domASTFunc{params: domASTParams(fl.ParameterList), body: fl.Body}
		}
	}
}

func (w *domASTWalker) registerFunc(fl *ast.FunctionLiteral) {
	if fl.Name == nil {
		return
	}
	w.funcs[fl.Name.Name.String()] = domASTFunc{params: domASTParams(fl.ParameterList), body: fl.Body}
}

func domASTParams(pl *ast.ParameterList) []string {
	if pl == nil {
		return nil
	}
	out := make([]string, 0, len(pl.List))
	for _, b := range pl.List {
		if id, ok := b.Target.(*ast.Identifier); ok {
			out = append(out, id.Name.String())
		}
	}
	return out
}

// walkStatement walks one statement, returning how many bindings it newly tainted. In the
// propagation phase every bind lands in the flat table; the sink pass re-walks with sinks on, so
// its binds are no-ops (first-write-wins) and only its decisions count.
func (w *domASTWalker) walkStatement(st ast.Statement, sc domScriptSrc, scope *domASTScope) int {
	switch s := st.(type) {
	case *ast.VariableStatement:
		return w.walkBindings(s.List, sc, scope)
	case *ast.LexicalDeclaration:
		return w.walkBindings(s.List, sc, scope)
	case *ast.ExpressionStatement:
		return w.walkExprStatement(s.Expression, sc, scope)
	case *ast.FunctionDeclaration:
		if s.Function != nil && s.Function.Body != nil {
			return w.walkBody(s.Function.Body, sc, scope)
		}
	case *ast.BlockStatement:
		n := 0
		for _, sub := range s.List {
			if !w.e.spend(1) {
				return n
			}
			n += w.walkStatement(sub, sc, scope)
		}
		return n
	case *ast.IfStatement:
		n := w.walkStatement(s.Consequent, sc, scope)
		if s.Alternate != nil {
			n += w.walkStatement(s.Alternate, sc, scope)
		}
		return n
	case *ast.ForStatement:
		n := w.walkForInitializer(s.Initializer, sc, scope)
		if s.Body != nil {
			n += w.walkStatement(s.Body, sc, scope)
		}
		return n
	case *ast.ForInStatement:
		n := w.walkForInto(s.Into, sc, scope)
		return n + w.walkStatement(s.Body, sc, scope)
	case *ast.ForOfStatement:
		n := w.walkForInto(s.Into, sc, scope)
		return n + w.walkStatement(s.Body, sc, scope)
	case *ast.WhileStatement:
		if s.Body != nil {
			return w.walkStatement(s.Body, sc, scope)
		}
	case *ast.DoWhileStatement:
		if s.Body != nil {
			return w.walkStatement(s.Body, sc, scope)
		}
	case *ast.TryStatement:
		n := 0
		if s.Body != nil {
			n += w.walkBody(s.Body, sc, scope)
		}
		if s.Catch != nil && s.Catch.Body != nil {
			n += w.walkBody(s.Catch.Body, sc, scope)
		}
		if s.Finally != nil {
			n += w.walkBody(s.Finally, sc, scope)
		}
		return n
	case *ast.ReturnStatement:
		if s.Argument != nil {
			return w.walkExprStatement(s.Argument, sc, scope)
		}
	case *ast.ThrowStatement:
		if s.Argument != nil {
			return w.walkExprStatement(s.Argument, sc, scope)
		}
	case *ast.SwitchStatement:
		n := w.walkExprStatement(s.Discriminant, sc, scope)
		for _, c := range s.Body {
			for _, sub := range c.Consequent {
				if !w.e.spend(1) {
					return n
				}
				n += w.walkStatement(sub, sc, scope)
			}
		}
		return n
	case *ast.LabelledStatement:
		if s.Statement != nil {
			return w.walkStatement(s.Statement, sc, scope)
		}
	case *ast.WithStatement:
		if s.Body != nil {
			return w.walkStatement(s.Body, sc, scope)
		}
	}
	return 0
}

// walkFunctionValue walks the body of a function literal used as a value - a handler assigned to
// window.onhashchange, an arrow callback - with the enclosing scope visible, as the IIFE and
// event-handler paths do. Other expressions walk nothing.
func (w *domASTWalker) walkFunctionValue(expr ast.Expression, sc domScriptSrc, scope *domASTScope) int {
	switch fn := expr.(type) {
	case *ast.FunctionLiteral:
		if fn.Body != nil {
			return w.walkBody(fn.Body, sc, w.childScope(fn, scope))
		}
	case *ast.ArrowFunctionLiteral:
		switch body := fn.Body.(type) {
		case *ast.BlockStatement:
			return w.walkBody(body, sc, w.childScope(fn, scope))
		case *ast.ExpressionBody:
			if body.Expression != nil {
				return w.walkExprStatement(body.Expression, sc, w.childScope(fn, scope))
			}
		}
	}
	return 0
}

// walkBody walks a function body. In the propagation phase its assignments bind into the flat
// table (the lexical pass saw them too); in the sink pass the body's sinks are decided with the
// enclosing scope visible.
func (w *domASTWalker) walkBody(body *ast.BlockStatement, sc domScriptSrc, scope *domASTScope) int {
	n := 0
	for _, sub := range body.List {
		if !w.e.spend(1) {
			return n
		}
		n += w.walkStatement(sub, sc, scope)
	}
	return n
}

func (w *domASTWalker) walkForInitializer(init ast.ForLoopInitializer, sc domScriptSrc, scope *domASTScope) int {
	switch h := init.(type) {
	case *ast.ForLoopInitializerVarDeclList:
		return w.walkBindings(h.List, sc, scope)
	case *ast.ForLoopInitializerLexicalDecl:
		return w.walkBindings(h.LexicalDeclaration.List, sc, scope)
	case *ast.ForLoopInitializerExpression:
		return w.walkExprStatement(h.Expression, sc, scope)
	}
	return 0
}

func (w *domASTWalker) walkForInto(into ast.ForInto, sc domScriptSrc, scope *domASTScope) int {
	switch h := into.(type) {
	case *ast.ForIntoVar:
		if h.Binding != nil {
			return w.walkBindings([]*ast.Binding{h.Binding}, sc, scope)
		}
	case *ast.ForIntoExpression:
		return w.walkExprStatement(h.Expression, sc, scope)
	}
	return 0
}

func (w *domASTWalker) walkBindings(list []*ast.Binding, sc domScriptSrc, scope *domASTScope) int {
	n := 0
	for _, b := range list {
		if b == nil || b.Initializer == nil {
			continue
		}
		id, ok := b.Target.(*ast.Identifier)
		if !ok {
			if w.sinksOn {
				w.scanSinkCalls(b.Initializer, sc, scope)
			}
			continue // destructuring: lost, same as the lexical pass
		}
		if _, isFn := b.Initializer.(*ast.FunctionLiteral); isFn {
			continue // registered by hoist; nothing taints a function value
		}
		if w.sinksOn {
			w.scanSinkCalls(b.Initializer, sc, scope)
		}
		if t, tainted := w.evalTaint(b.Initializer, sc, scope); tainted {
			t.via = append(append([]string{}, t.via...), id.Name.String())
			if scope.bind(id.Name.String(), t) {
				n++
			}
		}
	}
	return n
}

// walkExprStatement handles the statement-level expression forms: assignments (taint propagation
// and sink writes), calls (sink calls and callee re-entry), and any nested sink call inside a
// larger expression.
func (w *domASTWalker) walkExprStatement(expr ast.Expression, sc domScriptSrc, scope *domASTScope) int {
	switch x := expr.(type) {
	case *ast.AssignExpression:
		return w.walkAssign(x, sc, scope)
	case *ast.CallExpression:
		return w.walkCall(x, sc, scope)
	case *ast.SequenceExpression:
		n := 0
		for _, e := range x.Sequence {
			n += w.walkExprStatement(e, sc, scope)
		}
		return n
	default:
		if w.sinksOn {
			w.scanSinkCalls(expr, sc, scope)
		}
	}
	return 0
}

// walkAssign mirrors the lexical propagate+checkAssignSink pair: a plain identifier takes taint,
// a member write is a sink when the member names one, a safe sink is suppressed, and a computed
// target with a tainted value is unresolved, never silent.
func (w *domASTWalker) walkAssign(x *ast.AssignExpression, sc domScriptSrc, scope *domASTScope) int {
	// el.onclick = function(){ ... }: the handler's body runs later with this scope visible.
	return w.walkFunctionValue(x.Right, sc, scope) + w.walkAssignValue(x, sc, scope)
}

func (w *domASTWalker) walkAssignValue(x *ast.AssignExpression, sc domScriptSrc, scope *domASTScope) int {
	if w.sinksOn {
		w.scanSinkCalls(x.Right, sc, scope)
	}
	t, tainted := w.evalTaint(x.Right, sc, scope)
	switch lhs := x.Left.(type) {
	case *ast.Identifier:
		if tainted {
			t.via = append(append([]string{}, t.via...), lhs.Name.String())
			if scope.bind(lhs.Name.String(), t) {
				return 1
			}
		}
	case *ast.DotExpression:
		target := w.renderMember(x.Left)
		if w.sinksOn {
			if safe, _, isSafe, _ := sinkForAssignTarget(target); isSafe {
				if tainted {
					w.suppressSafeSink(sc, x.Left, safe, t)
				}
				return 0
			}
			if _, sink, _, isSink := sinkForAssignTarget(target); isSink {
				if tainted {
					// The Statement evidence is the whole sink line, as the lexical pass
					// recorded it, not the right-hand side alone.
					w.decideAST(sc, x, sink, t, true)
				} else {
					st := domStatement{text: w.sliceSource(x.Right), line: w.lineOf(x.Right)}
					w.e.noteUntraced(sc, st, sink.Match, w.sliceSource(x.Right))
				}
				return 0
			}
		}
		if tainted {
			n := 0
			if scope.bind(target, t) {
				n++
			}
			// The base object carries what its property carries: reading o after o.v = tainted is
			// not a clean read. Conservative, same direction as the lexer's order-insensitivity.
			if base, ok := lhs.Left.(*ast.Identifier); ok {
				if scope.bind(base.Name.String(), t) {
					n++
				}
			}
			return n
		}
	case *ast.BracketExpression:
		if !tainted {
			return 0
		}
		if _, literal := lhs.Member.(*ast.StringLiteral); literal {
			if scope.bind(w.renderMember(x.Left), t) {
				return 1
			}
			return 0
		}
		if w.sinksOn {
			w.e.addUnresolved(DOMUnresolved{
				Reason: DOMUnresolvedComputedAccess, Sink: w.renderMember(lhs.Left),
				Detail: t.sourceExpr, Script: sc.ref, Line: w.absLine(sc, x.Left),
				Statement: domClip(w.sliceSource(x.Left)),
			})
		}
	}
	return 0
}

// walkCall handles call statements: a sink call (document.write(t)), an event-handler function
// literal walked with the enclosing scope visible, and re-entry into a known callee with its
// parameters bound to the call's argument taints.
func (w *domASTWalker) walkCall(x *ast.CallExpression, sc domScriptSrc, scope *domASTScope) int {
	if w.sinksOn {
		if sink, isSink := sinkForCall(w.renderMember(x.Callee)); isSink {
			for _, arg := range x.ArgumentList {
				// setTimeout(function(){...}) is the safe, ordinary use: the string-sink rule is
				// checked before the argument's own text is scanned for sources, exactly like the
				// lexical domFirstArgIsFunction short-circuit.
				if sink.Form == DOMSinkCallString {
					switch arg.(type) {
					case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
						continue
					}
				}
				t, tainted := w.evalTaint(arg, sc, scope)
				w.decideAST(sc, arg, sink, t, tainted)
			}
			return 0
		}
		for _, arg := range x.ArgumentList {
			if isFunctionValue(arg) {
				w.walkFunctionValue(arg, sc, scope)
			} else {
				w.scanSinkCalls(arg, sc, scope)
			}
		}
	}
	// An IIFE: the callee is the function itself. Walk its body with the enclosing scope visible.
	// An IIFE: the callee is the function itself. Its body walks in both phases - its
	// assignments propagate, its sinks decide.
	switch fn := x.Callee.(type) {
	case *ast.FunctionLiteral:
		if fn.Body != nil {
			return w.walkBody(fn.Body, sc, w.childScope(fn, scope))
		}
		return 0
	case *ast.ArrowFunctionLiteral:
		if body, ok := fn.Body.(*ast.BlockStatement); ok {
			return w.walkBody(body, sc, w.childScope(fn, scope))
		}
		return 0
	}
	id, ok := x.Callee.(*ast.Identifier)
	if !ok {
		return 0
	}
	fn, known := w.funcs[id.Name.String()]
	if !known || w.visiting[id.Name.String()] || w.depth >= domASTMaxCallDepth {
		return 0
	}
	callScope := w.childScope(x, scope)
	for i, p := range fn.params {
		if i < len(x.ArgumentList) {
			if t, tainted := w.evalTaint(x.ArgumentList[i], sc, scope); tainted {
				t.via = append(append([]string{}, t.via...), p)
				callScope.bind(p, t)
			}
		}
	}
	w.visiting[id.Name.String()] = true
	w.depth++
	n := 0
	if fn.body != nil {
		n = w.walkBody(fn.body, sc, callScope)
	}
	w.depth--
	delete(w.visiting, id.Name.String())
	return n
}

// scanSinkCalls finds sink calls nested inside any expression - a var initializer
// (`var o = JSON.parse(location.hash)`), an assignment's right-hand side, a condition.
func (w *domASTWalker) scanSinkCalls(expr ast.Expression, sc domScriptSrc, scope *domASTScope) {
	switch x := expr.(type) {
	case *ast.CallExpression:
		if sink, isSink := sinkForCall(w.renderMember(x.Callee)); isSink {
			for _, arg := range x.ArgumentList {
				t, tainted := w.evalTaint(arg, sc, scope)
				w.decideAST(sc, arg, sink, t, tainted)
			}
			return
		}
		w.scanSinkCalls(x.Callee, sc, scope)
		for _, arg := range x.ArgumentList {
			w.scanSinkCalls(arg, sc, scope)
		}
	case *ast.NewExpression:
		if sink, isSink := sinkForCall(w.renderMember(x.Callee)); isSink {
			for _, arg := range x.ArgumentList {
				t, tainted := w.evalTaint(arg, sc, scope)
				w.decideAST(sc, arg, sink, t, tainted)
			}
		}
	case *ast.BinaryExpression:
		w.scanSinkCalls(x.Left, sc, scope)
		w.scanSinkCalls(x.Right, sc, scope)
	case *ast.UnaryExpression:
		w.scanSinkCalls(x.Operand, sc, scope)
	case *ast.ConditionalExpression:
		w.scanSinkCalls(x.Consequent, sc, scope)
		w.scanSinkCalls(x.Alternate, sc, scope)
	case *ast.TemplateLiteral:
		for _, sub := range x.Expressions {
			w.scanSinkCalls(sub, sc, scope)
		}
	case *ast.AssignExpression:
		w.scanSinkCalls(x.Right, sc, scope)
	case *ast.SequenceExpression:
		for _, e := range x.Sequence {
			w.scanSinkCalls(e, sc, scope)
		}
	case *ast.DotExpression:
		w.scanSinkCalls(x.Left, sc, scope)
	case *ast.BracketExpression:
		w.scanSinkCalls(x.Left, sc, scope)
		w.scanSinkCalls(x.Member, sc, scope)
	}
}

// evalTaint is the AST counterpart of the lexical evalTaint: a source token anywhere in the
// expression's own text wins over a tainted binding (the lexical rule, kept verbatim over the
// sliced source), then bindings by name, then the arguments or receiver of a call.
func (w *domASTWalker) evalTaint(expr ast.Expression, sc domScriptSrc, scope *domASTScope) (domTaint, bool) {
	text := w.sliceSource(expr)
	for _, src := range domSources {
		if domContainsToken(text, src.Expr) {
			t := domTaint{source: src, sourceExpr: src.Expr}
			for _, s := range domSanitizers {
				if domContainsToken(text, s.Call) {
					t.accepted = append(t.accepted, s)
				}
			}
			for _, we := range domWeakEncoders {
				if domContainsToken(text, we.Call) {
					t.weak = append(t.weak, we)
				}
			}
			return t, true
		}
	}
	switch x := expr.(type) {
	case *ast.Identifier:
		if t, ok := scope.lookup(x.Name.String()); ok {
			return t, true
		}
	case *ast.DotExpression:
		if t, ok := scope.lookup(w.renderMember(expr)); ok {
			return t, true
		}
		if base, isID := x.Left.(*ast.Identifier); isID {
			if t, ok := scope.lookup(base.Name.String()); ok {
				return t, true
			}
		}
	case *ast.BracketExpression:
		if t, ok := scope.lookup(w.renderMember(expr)); ok {
			return t, true
		}
		if t, ok := w.evalTaint(x.Left, sc, scope); ok {
			return t, true
		}
	case *ast.CallExpression, *ast.NewExpression:
		var args []ast.Expression
		var callee ast.Expression
		if c, isCall := expr.(*ast.CallExpression); isCall {
			args, callee = c.ArgumentList, c.Callee
		} else {
			n := expr.(*ast.NewExpression)
			args, callee = n.ArgumentList, n.Callee
		}
		var t domTaint
		found := false
		for _, arg := range args {
			if at, ok := w.evalTaint(arg, sc, scope); ok {
				t, found = at, true
				break
			}
		}
		if !found {
			if d, isDot := callee.(*ast.DotExpression); isDot {
				if bt, ok := w.evalTaint(d.Left, sc, scope); ok {
					t, found = bt, true
				}
			}
		}
		if !found {
			return domTaint{}, false
		}
		for _, s := range domSanitizers {
			if domContainsToken(text, s.Call) {
				t.accepted = append(t.accepted, s)
			}
		}
		for _, we := range domWeakEncoders {
			if domContainsToken(text, we.Call) {
				t.weak = append(t.weak, we)
			}
		}
		return t, true
	case *ast.BinaryExpression:
		if t, ok := w.evalTaint(x.Left, sc, scope); ok {
			return t, true
		}
		return w.evalTaint(x.Right, sc, scope)
	case *ast.TemplateLiteral:
		for _, sub := range x.Expressions {
			if t, ok := w.evalTaint(sub, sc, scope); ok {
				return t, true
			}
		}
	case *ast.ConditionalExpression:
		if t, ok := w.evalTaint(x.Consequent, sc, scope); ok {
			return t, true
		}
		return w.evalTaint(x.Alternate, sc, scope)
	case *ast.AssignExpression:
		return w.evalTaint(x.Right, sc, scope)
	case *ast.SequenceExpression:
		if n := len(x.Sequence); n > 0 {
			return w.evalTaint(x.Sequence[n-1], sc, scope)
		}
	}
	return domTaint{}, false
}

// ---- sink matching and reporting -------------------------------------------------------------

// sinkForAssignTarget classifies a member-write target against the safe list first, then the
// assign-form sink table - the same precedence as the lexical checkAssignSink.
func sinkForAssignTarget(target string) (safe string, sink DOMSink, isSafe, isSink bool) {
	for _, s := range domSafeSinks {
		if domTargets(target, s) {
			return s, DOMSink{}, true, false
		}
	}
	for _, sk := range domSinks {
		if sk.Form == DOMSinkAssign && domTargets(target, sk.Match) {
			return "", sk, false, true
		}
	}
	return "", DOMSink{}, false, false
}

// sinkForCall matches a rendered callee against the call-form sinks. A Match with a leading dot
// (".postMessage", ".html") is a method name: suffix match, as the lexer's raw token search found
// it. Anything else goes through the lexer's target rule.
func sinkForCall(callee string) (DOMSink, bool) {
	for _, sk := range domSinks {
		if sk.Form == DOMSinkAssign {
			continue
		}
		if strings.HasPrefix(sk.Match, ".") {
			if strings.HasSuffix(callee, sk.Match) {
				return sk, true
			}
			continue
		}
		if domTargets(callee, sk.Match) {
			return sk, true
		}
	}
	return DOMSink{}, false
}

// decideAST is the AST path into the engine's decide/noteUntraced judgement: it synthesises the
// lexical domStatement the reporting helpers expect (source text and a script-relative line).
func (w *domASTWalker) decideAST(sc domScriptSrc, node ast.Expression, sink DOMSink, t domTaint, tainted bool) {
	st := domStatement{text: w.sliceSource(node), line: w.lineOf(node)}
	if !tainted {
		if sink.Form == DOMSinkCallString {
			switch node.(type) {
			case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
				return // setTimeout(function(){...}): the pass knows exactly what this is
			}
		}
		if !domASTHasIdents(node) {
			return // a literal input is genuinely known not to be attacker-controlled
		}
		w.e.noteUntraced(sc, st, sink.Match, w.sliceSource(node))
		return
	}
	w.e.decide(sc, st, sink, t)
}

// suppressSafeSink records a tainted write to a text-only property.
func (w *domASTWalker) suppressSafeSink(sc domScriptSrc, node ast.Expression, safe string, t domTaint) {
	w.e.addSuppressed(DOMSuppressed{
		Reason: DOMSuppressReasonSafeSink,
		Source: t.source, SourceExpr: t.sourceExpr, Sink: safe, Via: t.via,
		By:        safe,
		Why:       "writing to " + safe + " inserts text, so the value cannot execute or navigate; Burp would catalogue this as info-level DOM data manipulation",
		Script:    sc.ref,
		Line:      w.absLine(sc, node),
		Statement: domClip(w.sliceSource(node)),
	})
}

// ---- rendering, positions --------------------------------------------------------------------

// renderMember renders a member/call-target expression to dotted text (location.hash,
// document.write) for table matching. An unrenderable receiver still leaves the property
// suffix-matchable (".innerHTML"), never an empty target.
func (w *domASTWalker) renderMember(expr ast.Expression) string {
	switch x := expr.(type) {
	case *ast.Identifier:
		return x.Name.String()
	case *ast.DotExpression:
		left := w.renderMember(x.Left)
		return left + "." + x.Identifier.Name.String()
	case *ast.BracketExpression:
		left := w.renderMember(x.Left)
		if sl, ok := x.Member.(*ast.StringLiteral); ok {
			return left + "." + sl.Value.String()
		}
		return left
	case *ast.CallExpression:
		return w.renderMember(x.Callee)
	case *ast.NewExpression:
		return w.renderMember(x.Callee)
	case *ast.ThisExpression:
		return "this"
	}
	return ""
}

// domASTHasIdents reports whether an expression mentions any identifier at all - the AST
// counterpart of the lexer's literal-vs-untraceable distinction.
func domASTHasIdents(expr ast.Expression) bool {
	switch x := expr.(type) {
	case *ast.Identifier, *ast.DotExpression, *ast.BracketExpression, *ast.CallExpression,
		*ast.NewExpression, *ast.ConditionalExpression, *ast.ThisExpression:
		return true
	case *ast.BinaryExpression:
		return domASTHasIdents(x.Left) || domASTHasIdents(x.Right)
	case *ast.UnaryExpression:
		return domASTHasIdents(x.Operand)
	case *ast.TemplateLiteral:
		for _, sub := range x.Expressions {
			if domASTHasIdents(sub) {
				return true
			}
		}
	case *ast.AssignExpression:
		return domASTHasIdents(x.Right)
	case *ast.SequenceExpression:
		return len(x.Sequence) > 0 && domASTHasIdents(x.Sequence[len(x.Sequence)-1])
	}
	return false
}

func (w *domASTWalker) lineOf(node ast.Expression) int {
	return w.fset.Position(node.Idx0()).Line
}

func (w *domASTWalker) absLine(sc domScriptSrc, node ast.Expression) int {
	return sc.ref.Line + w.lineOf(node) - 1
}

// sliceSource cuts the node's own text out of the script for the Statement evidence field and
// for the token scans the source and transform tables run on.
func (w *domASTWalker) sliceSource(node ast.Expression) string {
	from, to := int(node.Idx0())-1, int(node.Idx1())-1
	if from < 0 || to > len(w.src) || from >= to {
		return "<expr>"
	}
	return w.src[from:to]
}

// keep strings imported for the dotted-render helpers that need it.
var _ = strings.TrimSpace

// isFunctionValue reports whether expr is a function literal or an arrow function.
func isFunctionValue(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		return true
	}
	return false
}
