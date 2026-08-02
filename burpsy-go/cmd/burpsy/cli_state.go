package main

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// loadState opens the -db SQLite file (when one was given) and restores every
// store from it, then installs write-through sinks so all subsequent mutations
// are mirrored. With no -db flag this is a no-op and the CLI is purely
// in-memory — the same contract as the web UI without persistence.
func (ctx *cliContext) loadState() error {
	if ctx.dbPath == "" {
		return nil
	}
	p, err := persist.Open(ctx.dbPath, zap.NewNop())
	if err != nil {
		return err
	}
	ctx.persist = p
	if err := p.Restore(ctx.store, ctx.findings, ctx.scope, ctx.mr, ctx.sess, ctx.organizer, ctx.toolLog); err != nil {
		return fmt.Errorf("restore from %s: %w", ctx.dbPath, err)
	}
	// Mirror every append the way the proxy's store does.
	ctx.store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	ctx.findings.SetPersistenceSink(p.SaveFinding)
	ctx.toolLog.SetPersistenceSink(p.SaveToolLog)
	return nil
}

// saveState writes the mutable stores that are replaced wholesale rather than
// appended (scope, match & replace rules, session rules, organizer). It is a
// no-op when the CLI has no database open. Called after every mutating command.
func (ctx *cliContext) saveState() error {
	if ctx.persist == nil {
		return nil
	}
	p := ctx.persist
	p.SaveScope(ctx.scope.Rules())
	p.SaveMatchRules(ctx.mr.Rules(), ctx.mr.UpdateContentLength())
	p.SaveSessionRules(ctx.sess.AllRules())
	p.SaveOrganizer(ctx.organizer.List())
	return nil
}
