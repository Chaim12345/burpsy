package crawler

// The crawl's phases and where each location came from (burpsy-react-ui-hbjo).
//
// # Why a closed vocabulary rather than the free strings in use
//
// Every location the crawl admits carries a `tag` naming how it was found. Those tags are currently
// free strings written at twelve call sites, which means:
//
//   - nothing can COUNT them. A report can say "1,240 locations" and cannot say how many came from
//     the sitemap, how many from a JSON document, how many were mined out of a script body. So an
//     operator whose coverage looks wrong cannot ask where the crawl looked.
//   - nothing can CHECK them. A typo in one tag is a silent divergence — the string still reads as a
//     tag and nothing anywhere learns it was meant to be another one.
//
// So the values are declared once here, and a link's source is a typed field rather than a string.
//
// # These are burpsy's phases, not Burp's 23 action kinds
//
// Burp has 23 (Zb8w.java:7-30) because its crawler does considerably more than this one. Inventing
// 23 values burpsy never produces would be a table of absences, and an operator reading "0 API
// actions" cannot tell "this build does not do that" from "the crawl did not need to". Every phase
// below is something this crawler demonstrably does, and the count is stated so the difference is on
// the record rather than implied by silence.

// CrawlPhase is one stage of a crawl, as the report counts it.
//
// Ordered by when the crawl does them, which is why the string values carry a numeric prefix: a
// report rendered as a list reads in the order they happened, and a phase vocabulary an operator
// has to sort by hand is a vocabulary half of them will not use.
type CrawlPhase string

const (
	// PhaseSeeds is the operator's own starting points being queued. Present so "0 locations found"
	// is distinguishable from "the crawl never started", which a phase count answers and a total does not.
	PhaseSeeds CrawlPhase = "01-seeds"
	// PhaseRobots is the robots.txt probe, and PhaseRobotsSitemap the sitemap URLs it names.
	PhaseRobots         CrawlPhase = "02-robots"
	PhaseRobotsSitemap  CrawlPhase = "03-robots-sitemap"
	PhaseSitemap        CrawlPhase = "04-sitemap"
	PhaseRedirect       CrawlPhase = "05-redirect"
	PhaseRendered       CrawlPhase = "06-rendered"
	PhaseFrontierWalk   CrawlPhase = "07-frontier-walk"
	PhaseSpeculative    CrawlPhase = "08-speculative"
	PhaseJSONDocument   CrawlPhase = "09-json-document"
	PhaseAPIDocument    CrawlPhase = "10-api-document"
	PhaseGraphQL        CrawlPhase = "11-graphql"
	PhaseEmbeddedObject CrawlPhase = "12-embedded-object"
	// PhaseJavaScript is a location read out of a JavaScript response — an external bundle or its
	// source map — by the jsluice AST pass and burpsy's own path miner together (burpsy-react-ui-jwy5).
	PhaseJavaScript CrawlPhase = "13-javascript"
	// PhaseWellKnown is a standard .well-known document requested per seed authority (bc2x).
	PhaseWellKnown CrawlPhase = "14-well-known"
)

// CrawlPhaseAll is every phase, in order. A caller renders a legend from this rather than
// hard-coding the set, so a phase added later appears without a second edit.
var CrawlPhaseAll = []CrawlPhase{
	PhaseSeeds, PhaseRobots, PhaseRobotsSitemap, PhaseSitemap, PhaseRedirect,
	PhaseRendered, PhaseFrontierWalk, PhaseSpeculative, PhaseJSONDocument,
	PhaseAPIDocument, PhaseGraphQL, PhaseEmbeddedObject, PhaseJavaScript, PhaseWellKnown,
}

// PhaseOfTag maps a discovery tag to the phase that produced it.
//
// Returns PhaseNone for a tag this build does not recognise, deliberately and without an error. The
// vocabulary is the package's own, so an unrecognised value is either a caller who wants a phase
// burpsy does not have, or a future tag — and neither should fail a crawl over a label. What must not
// happen is the tag being counted under some other phase, which is why this returns an explicit
// "none" rather than defaulting to the first entry.
func PhaseOfTag(tag string) CrawlPhase {
	switch tag {
	case "a", "area", "button", "input", "math", "seed", "form", "":
		// A plain navigational link, a form, or a seed. All frontier walk, and grouping them is the
		// point: an operator asking "how much of this came from ordinary links" gets one number.
		return PhaseFrontierWalk
	case "iframe", "frame", "redirect", tagMetaRefresh, tagRefreshHeader:
		return PhaseRedirect
	case "object", "embed", "img", "source", "audio", "track", "video", "link":
		// Subresources (4ocj) are embedded content the page loads, the same phase as object/embed.
		return PhaseEmbeddedObject
	case "rendered":
		return PhaseRendered
	case "robots":
		return PhaseRobots
	case "robots-sitemap":
		return PhaseRobotsSitemap
	case "sitemap":
		return PhaseSitemap
	case "speculative":
		return PhaseSpeculative
	case "well-known":
		return PhaseWellKnown
	case "script":
		// An external script a page referenced, fetched to be read for locations (jwy5).
		return PhaseJavaScript
	default:
		// Prefixed families, which carry the document kind: "json:next", "api:openapi",
		// "graphql:Query.user".
		switch {
		case hasTagPrefix(tag, "json:"):
			return PhaseJSONDocument
		case hasTagPrefix(tag, "api:"):
			return PhaseAPIDocument
		case hasTagPrefix(tag, "graphql:"):
			return PhaseGraphQL
		case hasTagPrefix(tag, "js:"):
			return PhaseJavaScript
		case hasTagPrefix(tag, "rendered:"):
			// A request a rendered page issued at run time (hzzl) is the rendered pass's discovery.
			return PhaseRendered
		}
		return PhaseNone
	}
}

// PhaseNone is the phase of a tag this build does not recognise. Counted, never dropped: a location
// whose phase is unknown has still been found, and omitting it from the tally would make the phases
// sum to less than the locations reported.
const PhaseNone CrawlPhase = "00-unknown"

// hasTagPrefix reports whether tag starts with prefix.
func hasTagPrefix(tag, prefix string) bool {
	return len(tag) > len(prefix) && tag[:len(prefix)] == prefix
}

// EdgeKindsAll is Burp's crawl-telemetry edge vocabulary (burpsy-react-ui-ylr1), in report order:
// every kind is present in Report.EdgeKinds, zero included, so a kind the crawl never produced reads
// as 0 rather than as a key that is missing. burpsy's own discovery sources that Burp has no edge for
// (robots, sitemaps, well-known paths, embedded objects, scripts, JSON documents) are reported
// beside them under their own names.
var EdgeKindsAll = []string{
	"anchor", "form", "frame", "iframe", "area", "redirect", "delayed_redirect", "origin", "submit",
	"clickable", "speculative", "api", "soap", "graphql",
	"embedded", "subresource", "robots", "sitemap", "well_known", "script", "json",
}

// EdgeKindOfTag maps a discovered link's tag onto Burp's edge vocabulary.
func EdgeKindOfTag(tag string) string {
	switch tag {
	case "a":
		return "anchor"
	case "area", "frame", "iframe", "redirect", "form", "speculative", "script":
		return tag
	case tagMetaRefresh, tagRefreshHeader:
		return "delayed_redirect"
	case "seed", "":
		return "origin"
	case "button[formaction]", "input[formaction]":
		return "submit"
	case "math":
		return "anchor"
	case "object", "embed":
		return "embedded"
	case "img", "source", "audio", "track", "video", "link":
		return "subresource"
	case "robots":
		return "robots"
	case "robots-sitemap", "sitemap":
		return "sitemap"
	case "well-known":
		return "well_known"
	case "source map":
		return "speculative"
	}
	switch {
	case hasTagPrefix(tag, "api:wsdl"):
		return "soap"
	case hasTagPrefix(tag, "api:"):
		return "api"
	case hasTagPrefix(tag, "graphql:"):
		return "graphql"
	case hasTagPrefix(tag, "rendered"):
		return "clickable"
	case hasTagPrefix(tag, "json:"):
		return "json"
	case hasTagPrefix(tag, "js:"):
		return "script"
	}
	return "other"
}
