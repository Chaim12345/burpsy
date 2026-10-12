package vulnapp

// Client-side template injection fixtures (burpsy-react-ui-j1mk.39).
//
// The vulnerable pages run a real, if small, client-side template engine: user input becomes part
// of the template SOURCE and the engine evaluates it. Two engines are inlined because the harness
// has no network and must not depend on a CDN copy of AngularJS or Handlebars:
//
//   - cstiAngularEngine mirrors AngularJS 1.x's $compile/$interpolate on the points that matter
//     here: {{expr}} in text nodes, the ng-bind attribute, ng-non-bindable, undefined rendering as
//     the empty string, a parse error leaving the text uncompiled, and the documented escaped
//     interpolation markers \{\{ and \}\} rendering as a literal {{ and }}. Expressions are parsed
//     by a recursive-descent evaluator (numbers, strings, identifiers looked up on the scope,
//     unary/binary arithmetic and parentheses), never by eval.
//   - cstiMustacheEngine is logic-less Mustache: variables, sections, inverted sections, comments.
//
// The safe twins are the defenses real applications use: escaping the curly braces with the
// engine's own escape so the engine prints them literally, and pages that print numbers (a fixed
// "42", the digits of the input) without evaluating anything — the latter is the page the old
// constant-7*6 proof reported.

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

const cstiAngularEngine = `
function tplEval(src, scope) {
  var toks = [], re = /\s*(\d+(?:\.\d+)?|[A-Za-z_$][\w$]*|'[^']*'|"[^"]*"|\S)/g, m;
  while ((m = re.exec(src)) !== null) { if (m[1] !== undefined) toks.push(m[1]); }
  if (src.replace(/\s+/g, '') === '') throw new Error('empty expression');
  var i = 0;
  function peek() { return toks[i]; }
  function next() { return toks[i++]; }
  function expr() { var v = term(); while (peek() === '+' || peek() === '-') { var op = next(), r = term(); v = op === '+' ? v + r : v - r; } return v; }
  function term() { var v = unary(); while (peek() === '*' || peek() === '/' || peek() === '%') { var op = next(), r = unary(); v = op === '*' ? v * r : op === '/' ? v / r : v % r; } return v; }
  function unary() { if (peek() === '-') { next(); return -unary(); } if (peek() === '!') { next(); return !unary(); } return primary(); }
  function primary() {
    var t = next();
    if (t === undefined) throw new Error('unexpected end');
    if (t === '(') { var v = expr(); if (next() !== ')') throw new Error('missing )'); return v; }
    if (/^\d/.test(t)) return Number(t);
    if (/^['"]/.test(t)) return t.slice(1, -1);
    if (/^[A-Za-z_$]/.test(t)) { var v = scope[t]; while (peek() === '.') { next(); var k = next(); v = v == null ? undefined : v[k]; } return v; }
    throw new Error('unexpected ' + t);
  }
  var v = expr();
  if (i !== toks.length) throw new Error('trailing tokens');
  return v;
}
function tplInterpolate(text, scope) {
  var O = '', C = '';
  var t = text.split('\\{\\{').join(O).split('\\}\\}').join(C);
  try {
    t = t.replace(/\{\{([\s\S]*?)\}\}/g, function (_, e) { var v = tplEval(e, scope); return v == null ? '' : String(v); });
  } catch (e) {
    t = text.split('\\{\\{').join(O).split('\\}\\}').join(C);
  }
  return t.split(O).join('{{').split(C).join('}}');
}
function tplCompile(node, scope) {
  if (node.nodeType === 1) {
    if (node.hasAttribute('ng-non-bindable')) return;
    var b = node.getAttribute('ng-bind');
    if (b !== null) { try { var v = tplEval(b, scope); node.textContent = v == null ? '' : String(v); } catch (e) {} return; }
    for (var c = node.firstChild; c; c = c.nextSibling) tplCompile(c, scope);
  } else if (node.nodeType === 3) {
    node.data = tplInterpolate(node.data, scope);
  }
}
`

const cstiMustacheEngine = `
function mustache(tpl, data) {
  var re = /\{\{\s*([#^\/!]?)\s*([^}]*?)\s*\}\}/g, toks = [], last = 0, m;
  while ((m = re.exec(tpl)) !== null) {
    if (m.index > last) toks.push({t: 'text', v: tpl.slice(last, m.index)});
    toks.push({t: m[1] || 'var', v: m[2]});
    last = re.lastIndex;
  }
  if (last < tpl.length) toks.push({t: 'text', v: tpl.slice(last)});
  var root = {kids: []}, stack = [root];
  toks.forEach(function (k) {
    var top = stack[stack.length - 1];
    if (k.t === '#' || k.t === '^') { var n = {t: k.t, v: k.v, kids: []}; top.kids.push(n); stack.push(n); }
    else if (k.t === '/') { if (stack.length > 1) stack.pop(); }
    else if (k.t !== '!') top.kids.push(k);
  });
  function render(kids, ctx) {
    return kids.map(function (k) {
      if (k.t === 'text') return k.v;
      var v = ctx[k.v];
      if (k.t === 'var') return v == null ? '' : String(v);
      var truthy = Array.isArray(v) ? v.length > 0 : !!v;
      if (k.t === '#') return truthy ? render(k.kids, ctx) : '';
      return truthy ? '' : render(k.kids, ctx);
    }).join('');
  }
  return render(root.kids, data);
}
`

// cstiPage writes a page with the given body markup and script.
func cstiPage(w http.ResponseWriter, body, script string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dm</title></head>
<body>%s<script>%s</script></body></html>`, body, script)
}

// dmTemplatePage puts location.hash into the template region, then compiles it: the fragment is
// template source.
func dmTemplatePage(w http.ResponseWriter, _ *http.Request) {
	cstiPage(w, `<div ng-app id="app"><p id="out"></p></div>`, cstiAngularEngine+`
var taint = decodeURIComponent(location.hash.slice(1));
document.getElementById('out').textContent = taint;
tplCompile(document.getElementById('app'), {});`)
}

// dmSafeTemplatePage reflects the fragment as text and never compiles it.
func dmSafeTemplatePage(w http.ResponseWriter, _ *http.Request) {
	cstiPage(w, `<div id="out"></div>`, `
var taint = decodeURIComponent(location.hash.slice(1));
document.getElementById('out').textContent = taint;`)
}

// dmTemplateReflected is the classic case: the server HTML-escapes q (so no reflected XSS) into a
// region the client-side engine then compiles. HTML escaping does nothing to {{ }}.
func dmTemplateReflected(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	cstiPage(w, `<div ng-app id="app"><p>Results for: `+q+`</p></div>`,
		cstiAngularEngine+`tplCompile(document.getElementById('app'), {});`)
}

// dmSafeTemplateReflected is the same page with the braces escaped by the engine's own escape
// (\{ and \}), so the engine prints the expression instead of evaluating it.
func dmSafeTemplateReflected(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	q = strings.NewReplacer("{", `\{`, "}", `\}`).Replace(q)
	cstiPage(w, `<div ng-app id="app"><p>Results for: `+q+`</p></div>`,
		cstiAngularEngine+`tplCompile(document.getElementById('app'), {});`)
}

// dmTemplateBind reflects q into an ng-bind attribute, whose value the engine evaluates with no
// delimiters at all.
func dmTemplateBind(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	cstiPage(w, `<div ng-app id="app"><span ng-bind="`+q+`"></span></div>`,
		cstiAngularEngine+`tplCompile(document.getElementById('app'), {});`)
}

// dmTemplateMustache reflects q into a client-side Mustache template, rendered as text.
func dmTemplateMustache(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	cstiPage(w, `<script type="text/x-template" id="tpl">Hello `+q+`</script><div id="out"></div>`,
		cstiMustacheEngine+`
document.getElementById('out').textContent = mustache(document.getElementById('tpl').text, {});`)
}

// dmSafeTemplateNumbers prints numbers on their own and evaluates nothing: the digits of q, and
// "42 results" once a fragment is present. The template delimiters are stripped from the echoes, so
// a probe's expression never reappears verbatim — exactly the page a constant {{7*6}} -> "42" proof
// reported.
func dmSafeTemplateNumbers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	digits := strings.Map(func(c rune) rune {
		if c >= '0' && c <= '9' {
			return c
		}
		return -1
	}, q)
	strip := strings.NewReplacer("{", "", "}", "", "[", "", "]", "", "$", "", "#", "", "^", "", "/", "")
	cstiPage(w, `<p>Reference: `+digits+`</p><p>You searched for: `+html.EscapeString(strip.Replace(q))+`</p><p id="out"></p>`, `
var taint = decodeURIComponent(location.hash.slice(1)).replace(/[{}\[\]$#^\/]/g, '');
if (taint) { document.getElementById('out').textContent = '42 results for ' + taint; }`)
}

// cstiEndpoints returns the manifest entries. /dm/template stays first: the safe-twin test pairs
// every safe page with the first vulnerable endpoint of the row.
func cstiEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/dm/template", Row: "Client-side template injection", DOM: true,
			Note: "location.hash inserted into an Angular-style template region that is then compiled"},
		{Path: "/dm/template-reflected?q=shoes", Row: "Client-side template injection", DOM: true,
			Note: "q HTML-escaped by the server into a region a client-side {{ }} engine compiles"},
		{Path: "/dm/template-bind?q=greeting", Row: "Client-side template injection", DOM: true,
			Note: "q reflected into an ng-bind attribute, evaluated with no delimiters"},
		{Path: "/dm/template-mustache?q=guest", Row: "Client-side template injection", DOM: true,
			Note: "q reflected into a client-side Mustache template"},
		{Path: "/dm/safe/template", Row: "Client-side template injection", DOM: true, Safe: true,
			Note: "the fragment is reflected as text, never evaluated"},
		{Path: "/dm/safe/template-reflected?q=shoes", Row: "Client-side template injection", DOM: true, Safe: true,
			Note: "same engine, braces escaped with the engine's own \\{ \\} escape"},
		{Path: "/dm/safe/template-numbers?q=shoes", Row: "Client-side template injection", DOM: true, Safe: true,
			Note: "prints \"42\" and the input's digits on their own; evaluates nothing"},
	}
}

// registerCSTI serves the routes above.
func registerCSTI(mux *http.ServeMux) {
	mux.HandleFunc("/dm/template", dmTemplatePage)
	mux.HandleFunc("/dm/safe/template", dmSafeTemplatePage)
	mux.HandleFunc("/dm/template-reflected", dmTemplateReflected)
	mux.HandleFunc("/dm/safe/template-reflected", dmSafeTemplateReflected)
	mux.HandleFunc("/dm/template-bind", dmTemplateBind)
	mux.HandleFunc("/dm/template-mustache", dmTemplateMustache)
	mux.HandleFunc("/dm/safe/template-numbers", dmSafeTemplateNumbers)
}
