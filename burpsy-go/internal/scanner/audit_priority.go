package scanner

// Audit prioritisation (burpsy-react-ui-ftk2): Burp's audit queue is ordered by a priority score, not
// by submission order, so a time-bounded scan spends its budget on the items that expose the most.
//
// # Burp's rule, as documented (scanner/auditing.html, "Audit prioritization")
//
// "Each item is assigned a priority score that determines its position in the audit queue." The score
// is "weighted 80/20 in favor of attack surface exposure over interest level":
//
//   - Attack surface exposure: an item's insertion points compared with those of the other items in
//     the queue and the items already audited. "Items with many unique insertion points expand the
//     attack surface ... items that share most of their insertion points with existing audit items
//     contribute less new exposure", and it is recalculated as items are added.
//   - Interest level, three factors: a state-changing method (POST, PUT, PATCH, DELETE), HTML, JSON,
//     XML or other structured content, and authentication.
//
// # How burpsy computes it
//
// The decompiled tree has no readable scoring class for this, so the documented rule is implemented
// directly and the constants are burpsy's:
//
//   - An insertion point is identified by host, path (no query), kind and name. The same parameter on
//     two endpoints is two points of attack surface, and the same parameter on one endpoint is one,
//     however many captures carry it.
//   - The queue is ordered greedily. At each step every remaining item's exposure is the number of
//     its points not yet covered, divided by the largest such number among the remaining items, so
//     the most-exposing item scores 1. Its interest is the mean of the three factors (0, 1/3, 2/3 or
//     1). The item with the highest 0.8·exposure + 0.2·interest starts next, and its points become
//     covered. This is the "recalculates the priority scores of all items" step, applied each time
//     an item is placed.
//   - Ties keep the requested order. An item whose capture cannot be read scores nothing and keeps
//     its relative place at the end; the audit refuses it with its reason, as before.
//   - "Items already audited during the current scan" are the items earlier in the same session.
//     burpsy keeps no cross-session record of audited points, so a later sweep tick does not discount
//     points an earlier tick covered. gaps.md records this.
//   - Above maxPrioritisedItems the greedy pass would be quadratic in the batch, so a larger batch is
//     scored once without recomputation.

import (
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

const (
	exposureWeight = 0.8
	interestWeight = 0.2
	// maxPrioritisedItems bounds the greedy recomputation: n² comparisons over a sweep batch of
	// thousands would cost more than the ordering saves.
	maxPrioritisedItems = 2000
)

// AuditPriority is one item's place and score in the audit queue.
type AuditPriority struct {
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// Score is 0.8·Exposure + 0.2·Interest at the moment the item was placed.
	Score float64 `json:"score"`
	// Exposure is the item's share of new attack surface when placed, from 0 to 1.
	Exposure float64 `json:"exposure"`
	// NewPoints is how many of its insertion points no earlier item had.
	NewPoints int `json:"new_points"`
	// Interest is the mean of the three interest factors.
	Interest float64 `json:"interest"`
	// Unreadable is true when the capture could not be read, so the item was not scored.
	Unreadable bool `json:"unreadable,omitempty"`
}

type priorityItem struct {
	slot       int
	points     []string
	interest   float64
	unreadable bool
}

// priorityOrder returns the order in which a batch's slots start, and each placed item's score.
func (s *ActiveScanner) priorityOrder(ids []core.ExchangeID, cfg AuditConfig) ([]int, []AuditPriority) {
	items := make([]priorityItem, len(ids))
	for i, id := range ids {
		items[i] = s.priorityItemFor(i, id, cfg)
	}
	order := make([]int, 0, len(ids))
	scores := make([]AuditPriority, 0, len(ids))
	covered := map[string]bool{}
	newPoints := func(it priorityItem) int {
		n := 0
		for _, p := range it.points {
			if !covered[p] {
				n++
			}
		}
		return n
	}
	place := func(it priorityItem, fresh, maxNew int) {
		order = append(order, it.slot)
		row := AuditPriority{ExchangeID: ids[it.slot], NewPoints: fresh, Interest: it.interest, Unreadable: it.unreadable}
		if !it.unreadable {
			if maxNew > 0 {
				row.Exposure = float64(fresh) / float64(maxNew)
			}
			row.Score = exposureWeight*row.Exposure + interestWeight*row.Interest
		}
		scores = append(scores, row)
		for _, p := range it.points {
			covered[p] = true
		}
	}

	var readable, unreadable []priorityItem
	for _, it := range items {
		if it.unreadable {
			unreadable = append(unreadable, it)
		} else {
			readable = append(readable, it)
		}
	}

	if len(readable) > maxPrioritisedItems {
		// One scoring pass, no recomputation: exposure against the batch as it stands.
		maxNew := 0
		fresh := make([]int, len(readable))
		for i, it := range readable {
			fresh[i] = len(it.points)
			maxNew = max(maxNew, fresh[i])
		}
		idx := make([]int, len(readable))
		for i := range idx {
			idx[i] = i
		}
		score := func(i int) float64 {
			e := 0.0
			if maxNew > 0 {
				e = float64(fresh[i]) / float64(maxNew)
			}
			return exposureWeight*e + interestWeight*readable[i].interest
		}
		sort.SliceStable(idx, func(a, b int) bool { return score(idx[a]) > score(idx[b]) })
		for _, i := range idx {
			place(readable[i], fresh[i], maxNew)
		}
	} else {
		remaining := readable
		for len(remaining) > 0 {
			maxNew := 0
			fresh := make([]int, len(remaining))
			for i, it := range remaining {
				fresh[i] = newPoints(it)
				maxNew = max(maxNew, fresh[i])
			}
			best, bestScore := 0, -1.0
			for i, it := range remaining {
				e := 0.0
				if maxNew > 0 {
					e = float64(fresh[i]) / float64(maxNew)
				}
				// Strictly greater, so a tie keeps the requested order.
				if sc := exposureWeight*e + interestWeight*it.interest; sc > bestScore {
					best, bestScore = i, sc
				}
			}
			place(remaining[best], fresh[best], maxNew)
			remaining = append(remaining[:best:best], remaining[best+1:]...)
		}
	}
	for _, it := range unreadable {
		place(it, 0, 0)
	}
	return order, scores
}

// priorityItemFor reads one capture's insertion points and interest factors.
func (s *ActiveScanner) priorityItemFor(slot int, id core.ExchangeID, cfg AuditConfig) priorityItem {
	it := priorityItem{slot: slot}
	if s == nil || s.store == nil {
		it.unreadable = true
		return it
	}
	ex, err := s.store.GetExchange(id)
	if err != nil || ex == nil || ex.Request == nil {
		it.unreadable = true
		return it
	}
	msg, err := s.store.Get(*ex.Request)
	if err != nil || msg == nil {
		it.unreadable = true
		return it
	}
	raw := msg.Raw()
	endpoint := strings.ToLower(ex.Host) + "\x00" + strings.SplitN(ex.Path, "?", 2)[0]
	points, _ := bcheck.EnumerateWith(raw, cfg.insertionKinds(), cfg.enumerateOptions())
	// The priority ledger reflects the same ingestion shape the dispatch sees: a rejected
	// GraphQL document's argument points are not coverage the audit is about to run.
	if !s.ConfigSnapshot().DisableGraphQLIngest {
		points = filterGraphQLPointsByValidation(points)
	}
	for _, p := range points {
		it.points = append(it.points, endpoint+"\x00"+string(p.Kind)+"\x00"+p.Name)
	}
	it.points = uniqueStrings(it.points)

	factors := 0.0
	switch strings.ToUpper(ex.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		factors++
	}
	if structuredContent(string(msg.Header("Content-Type"))) || structuredContent(ex.Mime) {
		factors++
	}
	if len(msg.Header("Authorization")) > 0 || len(msg.Header("Cookie")) > 0 {
		factors++
	}
	it.interest = factors / 3
	return it
}

// structuredContent reports HTML, JSON, XML or another structured format, Burp's content-type factor.
func structuredContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, kind := range []string{"html", "json", "xml", "x-www-form-urlencoded", "multipart/form-data", "graphql", "yaml", "protobuf", "grpc"} {
		if strings.Contains(ct, kind) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
