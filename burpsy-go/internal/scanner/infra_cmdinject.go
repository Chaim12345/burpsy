package scanner

// OS command injection payload validation via shell AST parsing.
//
// Response-text heuristics cannot tell "the payload executed a second command" from "the
// application echoed the payload back". Parsing what the target's shell would see answers
// it structurally: a payload that introduces a new command node broke out of its quoting,
// and one that does not is inert no matter what the response body looks like.

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type BreakoutKind int

const (
	BreakoutNone BreakoutKind = iota
	BreakoutStatementSeparator
	BreakoutCommandSubstitution
	BreakoutPipeline
	// BreakoutUnparseable means the composed line is not valid shell. That is not a
	// breakout, but it is not proof of safety either: a different shell may accept it.
	BreakoutUnparseable
)

func (b BreakoutKind) String() string {
	switch b {
	case BreakoutNone:
		return "no additional command"
	case BreakoutStatementSeparator:
		return "additional statement"
	case BreakoutCommandSubstitution:
		return "command substitution"
	case BreakoutPipeline:
		return "pipeline"
	case BreakoutUnparseable:
		return "unparseable as shell"
	}
	return "unknown"
}

// IsBreakout excludes BreakoutUnparseable: an unparseable line proves nothing either way.
func (b BreakoutKind) IsBreakout() bool {
	return b == BreakoutStatementSeparator || b == BreakoutCommandSubstitution || b == BreakoutPipeline
}

type shellShape struct {
	statements    int
	substitutions int
	pipelineParts int
}

func shapeOf(line string) (shellShape, bool) {
	f, err := syntax.NewParser().Parse(strings.NewReader(line), "")
	if err != nil {
		return shellShape{}, false
	}
	shape := shellShape{statements: len(f.Stmts)}
	syntax.Walk(f, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CmdSubst:
			shape.substitutions++
		case *syntax.BinaryCmd:
			// `;` and newline yield separate Stmts; `&&`, `||` and `|` are BinaryCmd.
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				shape.pipelineParts++
			} else {
				shape.statements++
			}
		}
		return true
	})
	return shape, true
}

// ClassifyBreakout compares the command line the target would run with the payload against
// the same line carrying an inert value. Extra command nodes in the injected shape are the
// proof; identical shapes mean the payload stayed inside its quoting.
func ClassifyBreakout(baseline, injected string) BreakoutKind {
	base, baseOK := shapeOf(baseline)
	inj, injOK := shapeOf(injected)
	if !injOK {
		return BreakoutUnparseable
	}
	if !baseOK {
		return BreakoutUnparseable
	}
	switch {
	case inj.substitutions > base.substitutions:
		return BreakoutCommandSubstitution
	case inj.statements > base.statements:
		return BreakoutStatementSeparator
	case inj.pipelineParts > base.pipelineParts:
		return BreakoutPipeline
	}
	return BreakoutNone
}

// RenderShellTemplate substitutes value at the single placeholder in template.
func RenderShellTemplate(template, placeholder, value string) string {
	return strings.ReplaceAll(template, placeholder, value)
}

// PayloadBreaksOut is the common case: does payload escape the placeholder in template,
// judged against an inert baseline value.
func PayloadBreaksOut(template, placeholder, payload string) BreakoutKind {
	const inert = "inertvalue"
	return ClassifyBreakout(
		RenderShellTemplate(template, placeholder, inert),
		RenderShellTemplate(template, placeholder, payload),
	)
}
