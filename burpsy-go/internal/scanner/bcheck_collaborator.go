package scanner

// The scanner's half of BCheck collaborator checks (burpsy-react-ui-ar8v): the evaluator's
// Collaborator seam bound to this scan's out-of-band channel, and the hand-off of a run whose
// interactions conditions were still unknown to the pending registry.
//
// Nothing here is new machinery. The channel is the scan-lifetime one the built-in out-of-band
// rows use (oob_channel.go), addresses are marker-prefixed onto its domain exactly as theirs are,
// and the wait is the registry's (pending.go), settled in FinishScan after the audit — so a
// corpus check neither blocks its audit item nor loses a callback that lands after it returns.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/oob"
)

// bcheckCollaborator adapts the scan's OOB channel to bcheck.Collaborator.
type bcheckCollaborator struct {
	sc  *ActiveScanner
	ctx context.Context

	mu  sync.Mutex
	ch  OOBChannel
	err error
	got bool
}

// bcheckCollaboratorFor returns the scan's collaborator for a corpus check, or nil when this scan
// has no out-of-band provider at all ("Don't use Burp Collaborator", or none configured) — which
// the evaluator turns into a refusal naming the reason, never a run with empty addresses.
//
// The channel itself is opened on the first address minted, not here: a check that never reaches
// generate_collaborator_address() (an insertion-point check on a request with no points) does not
// register a public collaborator domain for nothing.
func (s *ActiveScanner) bcheckCollaboratorFor(ctx context.Context) bcheck.Collaborator {
	if s == nil {
		return nil
	}
	s.oobMu.Lock()
	p := s.oob
	s.oobMu.Unlock()
	if p == nil {
		return nil
	}
	return &bcheckCollaborator{sc: s, ctx: ctx}
}

func (b *bcheckCollaborator) channel() (OOBChannel, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.got {
		b.got = true
		b.ch, b.err = b.sc.OOBChannel(b.ctx)
	}
	return b.ch, b.err
}

// NewAddress mints `<marker>.<domain>`. The marker is 64 random bits, so two calls — two probes,
// two insertion points, two concurrent checks — never share an address, and the channel's
// marker filter attributes each callback to the one call that planted it.
func (b *bcheckCollaborator) NewAddress() (string, error) {
	ch, err := b.channel()
	if err != nil {
		return "", err
	}
	domain := ch.Domain()
	if domain == "" {
		return "", fmt.Errorf("the out-of-band channel has no registered domain")
	}
	return newCollaboratorMarker() + "." + domain, nil
}

// newCollaboratorMarker is a fresh payload label: "bc" and 16 lowercase hex digits.
func newCollaboratorMarker() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand does not fail on supported platforms; a marker that could repeat would
		// misattribute callbacks, so this is not papered over.
		panic(fmt.Sprintf("collaborator marker: %v", err))
	}
	return "bc" + hex.EncodeToString(buf[:])
}

// Interactions reads the channel for the callbacks one minted address received.
func (b *bcheckCollaborator) Interactions(address string) ([]bcheck.Interaction, error) {
	ch, err := b.channel()
	if err != nil {
		return nil, err
	}
	marker, _, ok := strings.Cut(address, ".")
	if !ok || marker == "" {
		return nil, fmt.Errorf("collaborator address %q carries no marker", address)
	}
	got, err := ch.InteractionsFor(marker)
	if err != nil {
		return nil, err
	}
	out := make([]bcheck.Interaction, 0, len(got))
	for _, in := range oob.Deduplicate(got) {
		detail := strings.ToUpper(in.Protocol) + " interaction"
		if in.QType != "" {
			detail += " (" + in.QType + " query)"
		}
		detail += " for " + address
		if in.RemoteAddress != "" {
			if strings.EqualFold(in.Protocol, "dns") {
				// oob/AGENTS.md: for DNS this is the upstream resolver, never the target.
				detail += " via resolver " + in.RemoteAddress
			} else {
				detail += " from " + in.RemoteAddress
			}
		}
		if !in.Timestamp.IsZero() {
			detail += " at " + in.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, bcheck.Interaction{
			Protocol: strings.ToLower(in.Protocol),
			Address:  address,
			From:     in.RemoteAddress,
			Detail:   detail,
		})
	}
	return out, nil
}

// interactionEvidence renders a collaborator finding's callbacks as its evidence line.
func interactionEvidence(ins []bcheck.Interaction) string {
	parts := make([]string, 0, len(ins))
	for _, in := range ins {
		parts = append(parts, in.Detail)
	}
	return strings.Join(parts, "; ")
}

// convertBCheckFindings turns evaluator findings into scanner findings for exchange ex, with a
// collaborator finding's interactions as its evidence.
func convertBCheckFindings(fs []bcheck.Finding, ex *core.Exchange) []*Finding {
	out := make([]*Finding, 0, len(fs))
	for _, f := range fs {
		converted := bcheckFindingToScannerFinding(f, ex)
		if len(f.Interactions) > 0 {
			converted.Evidence = interactionEvidence(f.Interactions)
		}
		EnrichFinding(converted)
		out = append(out, converted)
	}
	return out
}

// registerBCheckDeferred hands each still-unknown run of a collaborator check to the pending
// registry, which replays it (bcheck.Deferred.Resolve — no traffic) on every poll until its
// conditions are decided or the deadline passes. It returns how many runs it registered.
func (s *ActiveScanner) registerBCheckDeferred(ex *core.Exchange, check *bcheck.Check, ds []*bcheck.Deferred) (int, error) {
	deadline := nowUTC().Add(DefaultPendingDeadline)
	if cfg := s.ConfigSnapshot(); cfg.PendingDeadline > 0 {
		deadline = nowUTC().Add(cfg.PendingDeadline)
	}
	n := 0
	for _, d := range ds {
		d := d
		where := ex.Path
		if p := d.Param(); p != "" {
			where = fmt.Sprintf("%s (insertion point %q)", ex.Path, p)
		}
		item := PendingItem{
			Row:      "BCheck: " + check.Name,
			Exchange: ex.ID,
			Deadline: deadline,
			What: fmt.Sprintf("BCheck %q sent %d probe(s) to %s carrying collaborator address(es) %s, awaiting the interactions its conditions ask about",
				check.Name, d.Probes(), where, strings.Join(d.Addresses(), ", ")),
		}
		err := s.Pending().RegisterBatch(item, func(context.Context) ([]*Finding, bool, error) {
			fs, settled, err := d.Resolve()
			if err != nil {
				// Kept, never settled: a replay that could not finish has not shown the target clean.
				return nil, false, fmt.Errorf("BCheck %q: %w", check.Name, err)
			}
			return convertBCheckFindings(fs, ex), settled, nil
		})
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
