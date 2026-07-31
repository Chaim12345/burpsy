// Package bcheck provides the BCheck DSL parser and evaluator.
package bcheck

import (
	"fmt"
)

// Check represents a parsed BCheck file.
type Check struct {
	Name        string
	Version     string
	Given       string
	Metadata    Metadata
	Statements  []Statement
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
	Collection string
	Iterator   string
	Body       []Statement
}

func (RunForEachStatement) isStatement() {}

// BoolExpr represents a boolean expression.
type BoolExpr struct {
	Left     Value
	Operator string
	Right    Value
}

// Value represents a BCheck value.
type Value struct {
	Type      string
	StringVal string
	BoolVal   bool
	IntVal    int
}

// CmpOp represents a comparison operator.
type CmpOp string

const (
	CmpEq        CmpOp = "eq"
	CmpNe        CmpOp = "ne"
	CmpLt        CmpOp = "lt"
	CmpGt        CmpOp = "gt"
	CmpLe        CmpOp = "le"
	CmpGe        CmpOp = "ge"
	CmpContains  CmpOp = "contains"
	CmpMatches   CmpOp = "matches"
)

// Severity represents issue severity.
type Severity string

const (
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Informational"
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

// RunPassive runs passive checks on a response.
func RunPassive(check *Check, ctx *Context) ([]Finding, error) {
	var findings []Finding

	if check.Given != "response" {
		return findings, nil
	}

	// Execute statements
	for _, stmt := range check.Statements {
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
		// Would iterate collection
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

func evalBoolExpr(expr BoolExpr, ctx *Context) bool {
	// Simplified evaluation
	left := expr.Left.StringVal
	right := expr.Right.StringVal

	switch expr.Operator {
	case "eq":
		return left == right
	case "ne":
		return left != right
	case "contains":
		return contains(left, right)
	case "matches":
		// Would use regex in full implementation
		return contains(left, right)
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
