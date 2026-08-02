package main

import (
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

func init() {
	registerCLI(
		&cliCommand{
			name:  "scope",
			usage: "manage the scope: burpsy scope (list|add|remove|clear)",
			run:   cmdScope,
		},
	)
}

// scopeRuleKind parses "include"/"exclude" into core.ScopeRuleKind, mirroring
// the wire strings the UI and the scope API use.
func scopeRuleKind(s string) (core.ScopeRuleKind, error) {
	switch strings.ToLower(s) {
	case "include", "in":
		return core.ScopeInclude, nil
	case "exclude", "out":
		return core.ScopeExclude, nil
	default:
		return 0, fmt.Errorf("scope kind must be 'include' or 'exclude', got %q", s)
	}
}

func kindString(k core.ScopeRuleKind) string {
	if k == core.ScopeExclude {
		return "exclude"
	}
	return "include"
}

func cmdScope(ctx *cliContext, args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		return scopeList(ctx, args)
	case "add":
		return scopeAdd(ctx, args)
	case "remove":
		return scopeRemove(ctx, args)
	case "clear":
		ctx.scope.Clear()
		ctx.saveState()
		fmt.Fprintln(ctx.out, "scope cleared")
		return nil
	default:
		return fmt.Errorf("usage: burpsy scope (list|add|remove|clear) — see 'burpsy help'")
	}
}

func scopeList(ctx *cliContext, args []string) error {
	fs := newFlagSet("scope list")
	jsonOut := fs.Bool("json", false, "emit the ShapeInfo object the UI uses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules := ctx.scope.Rules()
	if *jsonOut {
		views := make([]map[string]interface{}, 0, len(rules))
		for _, r := range rules {
			kind := "Include"
			if r.Kind == core.ScopeExclude {
				kind = "Exclude"
			}
			views = append(views, map[string]interface{}{"kind": kind, "host": r.Pattern})
		}
		return printJSON(ctx.out, map[string]interface{}{
			"allow_all": ctx.scope.AllowAll(),
			"empty":     ctx.scope.Empty(),
			"rules":     views,
		})
	}
	if ctx.scope.AllowAll() {
		fmt.Fprintln(ctx.out, "scope allows everything")
		return nil
	}
	if ctx.scope.Empty() {
		fmt.Fprintln(ctx.out, "scope is empty (refuses everything)")
		return nil
	}
	for _, r := range rules {
		fmt.Fprintf(ctx.out, "%-8s %s\n", kindString(r.Kind), r.Pattern)
	}
	return nil
}

func scopeAdd(ctx *cliContext, args []string) error {
	fs := newFlagSet("scope add")
	kind := fs.String("kind", "", "include | exclude")
	pattern := fs.String("pattern", "", "host pattern")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" && fs.NArg() > 0 {
		*kind = fs.Arg(0)
	}
	if *pattern == "" && fs.NArg() > 1 {
		*pattern = fs.Arg(1)
	}
	k, err := scopeRuleKind(*kind)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*pattern) == "" {
		return fmt.Errorf("usage: burpsy scope add -kind include|exclude -pattern HOST")
	}
	switch k {
	case core.ScopeInclude:
		ctx.scope.AddInclude(*pattern)
	case core.ScopeExclude:
		ctx.scope.AddExclude(*pattern)
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "added %s %s\n", kindString(k), *pattern)
	return nil
}

func scopeRemove(ctx *cliContext, args []string) error {
	fs := newFlagSet("scope remove")
	kind := fs.String("kind", "", "include | exclude")
	pattern := fs.String("pattern", "", "host pattern")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" && fs.NArg() > 0 {
		*kind = fs.Arg(0)
	}
	if *pattern == "" && fs.NArg() > 1 {
		*pattern = fs.Arg(1)
	}
	k, err := scopeRuleKind(*kind)
	if err != nil {
		return err
	}
	if !ctx.scope.Remove(k, *pattern) {
		return fmt.Errorf("no %s rule matches %q", kindString(k), *pattern)
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "removed %s %s\n", kindString(k), *pattern)
	return nil
}
