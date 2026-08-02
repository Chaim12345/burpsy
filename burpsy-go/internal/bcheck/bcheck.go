// Package bcheck provides the BCheck DSL parser and evaluator.
package bcheck

import (
	"fmt"
	"regexp"
	"strconv"
)

// Check represents a parsed BCheck file.
type Check struct {
	Name       string
	Version    string
	Given      string
	Metadata   Metadata
	Defines    []DefineStatement
	ForEach    []RunForEachStatement
	Statements []Statement
}

// Metadata holds check metadata.
type Metadata struct {
	Author      string
	Severity    string
	Confidence  string
	Description string
	Reference   []string
}

// Statement represents a BCheck statement.
type Statement interface {
	isStatement()
}

// IfStatement represents an if statement.
type IfStatement struct {
	Condition BoolExpr
	Then      []Statement
	Else      []Statement
}

func (IfStatement) isStatement() {}

// ReportIssueStatement represents a report issue statement.
type ReportIssueStatement struct {
	IssueName   string
	Severity    string
	Confidence  string
	Description string
	Remediation string
}

func (ReportIssueStatement) isStatement() {}

// DefineStatement represents a define statement.
type DefineStatement struct {
	Name  string
	Value Value
}

func (DefineStatement) isStatement() {}

// SendRequestStatement represents a send request statement.
type SendRequestStatement struct {
	Template string
	StoreAs  string
}

func (SendRequestStatement) isStatement() {}

// RunForEachStatement represents a run for each statement.
type RunForEachStatement struct {
	Iterator string
	Values   []Value
	Body     []Statement
}

func (RunForEachStatement) isStatement() {}

// BoolExpr represents a boolean expression.
// For a comparison, Left/Operator/Right are set. For logical composition
// (Operator "and", "or", "not") the operands live in LHS/RHS instead.
type BoolExpr struct {
	Left     Value
	Operator string
	Right    Value
	LHS      *BoolExpr
	RHS      *BoolExpr
}

// Value represents a BCheck value.
type Value struct {
	Type      string // "str", "var", "bool", "int"
	StringVal string
	BoolVal   bool
	IntVal    int
}

// CmpOp represents a comparison operator.
type CmpOp string

const (
	CmpEq       CmpOp = "eq"
	CmpNe       CmpOp = "ne"
	CmpLt       CmpOp = "lt"
	CmpGt       CmpOp = "gt"
	CmpLe       CmpOp = "le"
	CmpGe       CmpOp = "ge"
	CmpContains CmpOp = "contains"
	CmpMatches  CmpOp = "matches"
)

// Severity represents issue severity.
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	SeverityLow    Severity = "Low"
	SeverityInfo   Severity = "Informational"
)

// Confidence represents issue confidence.
type Confidence string

const (
	ConfidenceCertain   Confidence = "Certain"
	ConfidenceFirm      Confidence = "Firm"
	ConfidenceTentative Confidence = "Tentative"
)

// ParseError represents a parsing error.
type ParseError struct {
	Message string
	Line    int
	Column  int
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d:%d: %s", e.Line, e.Column, e.Message)
}

// Unsupported represents an unsupported feature.
type Unsupported struct {
	Feature string
}

func (u Unsupported) Error() string {
	return fmt.Sprintf("unsupported: %s", u.Feature)
}

// Finding represents a finding from check execution.
type Finding struct {
	IssueName   string
	Severity    Severity
	Confidence  Confidence
	Description string
	Remediation string
	RequestID   uint64
}

// Context holds the execution context.
type Context struct {
	Variables map[string]Value
	Request   []byte
	Response  []byte
	Host      string
	Path      string
}

// NewContext creates a new execution context.
func NewContext() *Context {
	return &Context{
		Variables: make(map[string]Value),
	}
}

// resolveVar resolves a variable reference against the context.
// Supports {name} definitions, {check.response}/{latest.response}/{base.response}
// and request/response fields. Unknown references resolve to the empty string.
func (ctx *Context) resolveVar(name string) string {
	if v, ok := ctx.Variables[name]; ok {
		return v.StringVal
	}
	switch name {
	case "check.response", "latest.response", "base.response":
		return string(ctx.Response)
	case "check.request", "latest.request", "base.request":
		return string(ctx.Request)
	case "host":
		return ctx.Host
	case "path":
		return ctx.Path
	}
	return ""
}

// resolveValue resolves a Value to its string form.
func (ctx *Context) resolveValue(v Value) string {
	switch v.Type {
	case "var":
		return ctx.resolveVar(v.StringVal)
	case "bool":
		if v.BoolVal {
			return "true"
		}
		return "false"
	case "int":
		return strconv.Itoa(v.IntVal)
	default:
		return v.StringVal
	}
}

// RunPassive runs passive checks on a response.
func RunPassive(check *Check, ctx *Context) ([]Finding, error) {
	var findings []Finding

	if check.Given != "response" {
		return findings, nil
	}

	// Execute statements. If the check declares `run for each`, iterate the
	// first iterable (one value per run, matching the corpus usage).
	statements := prependDefines(check.Defines, check.Statements)
	if len(check.ForEach) > 0 {
		fe := check.ForEach[0]
		for _, v := range fe.Values {
			ctx.Variables[fe.Iterator] = v
			for _, stmt := range statements {
				result, err := executeStatement(stmt, ctx)
				if err != nil {
					return nil, err
				}
				if result != nil {
					findings = append(findings, *result)
				}
			}
		}
		return findings, nil
	}

	// Execute statements
	for _, stmt := range statements {
		result, err := executeStatement(stmt, ctx)
		if err != nil {
			return nil, err
		}
		if result != nil {
			findings = append(findings, *result)
		}
	}

	return findings, nil
}

// prependDefines converts the defines slice to statements and prefixes the body.
func prependDefines(defines []DefineStatement, body []Statement) []Statement {
	out := make([]Statement, 0, len(defines)+len(body))
	for i := range defines {
		out = append(out, &defines[i])
	}
	return append(out, body...)
}

func executeStatement(stmt Statement, ctx *Context) (*Finding, error) {
	switch s := stmt.(type) {
	case *IfStatement:
		return executeIf(s, ctx)
	case *ReportIssueStatement:
		return &Finding{
			IssueName:   s.IssueName,
			Severity:    Severity(s.Severity),
			Confidence:  Confidence(s.Confidence),
			Description: s.Description,
			Remediation: s.Remediation,
		}, nil
	case *DefineStatement:
		ctx.Variables[s.Name] = s.Value
	case *SendRequestStatement:
		// Would send request in active checks
	case *RunForEachStatement:
		// Iterate the collection, binding the iterator for each value.
		for _, v := range s.Values {
			ctx.Variables[s.Iterator] = v
			for _, body := range s.Body {
				result, err := executeStatement(body, ctx)
				if err != nil {
					return nil, err
				}
				if result != nil {
					return result, nil
				}
			}
		}
	}
	return nil, nil
}

func executeIf(stmt *IfStatement, ctx *Context) (*Finding, error) {
	if evalBoolExpr(stmt.Condition, ctx) {
		for _, s := range stmt.Then {
			result, err := executeStatement(s, ctx)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
		}
	} else if stmt.Else != nil {
		for _, s := range stmt.Else {
			result, err := executeStatement(s, ctx)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
		}
	}
	return nil, nil
}

// evalBoolExpr evaluates a boolean expression against the context.
func evalBoolExpr(expr BoolExpr, ctx *Context) bool {
	switch expr.Operator {
	case "and":
		if expr.LHS == nil || expr.RHS == nil {
			return false
		}
		return evalBoolExpr(*expr.LHS, ctx) && evalBoolExpr(*expr.RHS, ctx)
	case "or":
		if expr.LHS == nil || expr.RHS == nil {
			return false
		}
		return evalBoolExpr(*expr.LHS, ctx) || evalBoolExpr(*expr.RHS, ctx)
	case "not":
		if expr.LHS == nil {
			return false
		}
		return !evalBoolExpr(*expr.LHS, ctx)
	}

	left := ctx.resolveValue(expr.Left)
	right := ctx.resolveValue(expr.Right)

	switch expr.Operator {
	case "eq", "is":
		return left == right
	case "ne":
		return left != right
	case "contains":
		return contains(left, right)
	case "in":
		// `x in y` — containment with the needle on the LEFT.
		return contains(right, left)
	case "matches":
		re, err := regexp.Compile(right)
		if err != nil {
			return false
		}
		return re.MatchString(left)
	}
	return false
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
