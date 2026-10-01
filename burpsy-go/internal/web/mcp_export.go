package web

import (
	"net/http"
	"sort"
	"strings"
)

// The exported surface the MCP transport (burpsy-react-ui-q31t) needs from this package.
//
// This file adds names and changes no line that already exists. The manifest, the risk taxonomy and
// the gated handler are deliberately unexported: they are one server's internals, and route_manifest.go
// keeps them unexported so that a route cannot be declared in one file and enforced in another. A
// second transport needs to READ that single source — the point of the whole arrangement is that a
// tool's risk class is derived from its route's risk class, never written twice — so the wrappers
// below expose read-only views of what already exists rather than a second copy of it.
//
// A copy is the specific failure this avoids. A hand-maintained list of routes, risks and
// confirm-worthy classes in the MCP package would agree with the manifest on the day it was written
// and disagree on the day a route was added, with nothing to say which of the two is right. Here a
// missing route shows up as a missing tool and a changed risk class shows up as a changed tool, both
// at once, with no second edit to forget.

// MCPRouteInfo is one manifest route as the MCP transport needs it: what to call it on the wire, what
// it accepts, and what it is allowed to do.
//
// Every field is derived, not authored: the transport reads this and the test asserts the two agree,
// so a route added to the manifest becomes a tool without anyone editing the MCP package at all.
type MCPRouteInfo struct {
	// Pattern is the ServeMux pattern the server registered, verbatim — "/api/history",
	// "/api/audit/". It is what the gate resolves a request to and what a confirmation token is
	// issued against, so it is carried as-is rather than prettified.
	Pattern string `json:"pattern"`
	// Methods is every verb the handler answers. A transport that exposes a verb the handler does
	// not implement would advertise a tool that answers 405.
	Methods []string `json:"methods"`
	// Summary is the manifest's own one-line description of the route.
	Summary string `json:"summary"`
	// Risk is the manifest's riskClass, the field that says what an unattended caller may do here.
	Risk string `json:"risk"`
	// Safety is the sentence derived from Risk by toolSafety, shared with the console's own agent
	// tool registry rather than reworded for the MCP wire.
	Safety string `json:"safety"`
	// Tier is the escalation tier derived from Risk by toolTier, again shared with the registry
	// rather than re-derived. It is what separates "a read" from "a local write" for a host that
	// gates on tiers rather than on route names.
	Tier string `json:"tier"`
	// Hints is the hint set derived from Risk by toolHints (READ_ONLY, IDEMPOTENT, OPEN_WORLD,
	// DESTRUCTIVE). MCP has standard boolean annotations for exactly these four properties, so the
	// transport maps them rather than judging each route again for itself.
	Hints []string `json:"hints"`
	// NeedsConfirm reports whether this route's risk class is one needsConfirmation covers.
	// Confirmation is NOT optional for these classes, and it is not decided in the transport.
	NeedsConfirm bool `json:"needs_confirm"`
	// SubPath is a concrete path under a subtree pattern — "/api/audit/" needs an id before it is
	// requestable. Empty for exact patterns. Carried so a transport can document a requestable
	// example and refuse a subtree pattern the caller did not complete, instead of silently
	// sending the bare prefix.
	SubPath string `json:"sub_path,omitempty"`
	// PathValidatedFirst reports that the handler resolves its path segment before checking the
	// method, so an unknown segment answers 404 rather than 405 whatever the verb.
	PathValidatedFirst bool `json:"path_validated_first,omitempty"`
}

// mcpRouteInfoOf flattens one manifest entry. One constructor for every reader, so a field added to
// MCPRouteInfo cannot reach the tool list but not the path resolver.
func mcpRouteInfoOf(pattern string, r route) MCPRouteInfo {
	return MCPRouteInfo{
		Pattern:            pattern,
		Methods:            append([]string(nil), r.methods...),
		Summary:            r.summary,
		Risk:               string(r.risk),
		Safety:             toolSafety(r.risk),
		Tier:               toolTier(r.risk),
		Hints:              toolHints(r.risk),
		NeedsConfirm:       needsConfirmation(r.risk),
		SubPath:            r.subPath,
		PathValidatedFirst: r.pathValidatedFirst,
	}
}

// MCPRoutes returns every route in the manifest, sorted by pattern.
//
// Sorted because the manifest is a map: an unordered tool list makes two identical tools/list calls
// return two different orders, which reads as an unstable server to a client and makes a diff of two
// transcripts meaningless.
func MCPRoutes() []MCPRouteInfo {
	out := make([]MCPRouteInfo, 0, len(manifest))
	for pattern, r := range manifest {
		out = append(out, mcpRouteInfoOf(pattern, r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

// MCPRouteRisk answers the manifest's risk class for a route pattern.
func MCPRouteRisk(pattern string) (string, bool) {
	r, ok := manifest[pattern]
	if !ok {
		return "", false
	}
	return string(r.risk), true
}

// MCPRouteForPath resolves a concrete request PATH to the manifest route it names, using the same
// longest-prefix rule the gate uses.
//
// This is the binding between a tool and the route it may reach, and it is what stops a call from
// naming one route and reaching another: a tool listed as /api/advisories that could be pointed at
// /api/audit/selected would be a descriptor whose published risk class describes a route other than
// the one it reaches. Delegating to routeRiskFor — rather than comparing prefixes here — is what
// keeps the binding and the gate from ever disagreeing about which route a path names.
//
// A path that resolves nowhere is reported as not-found rather than as an error: "there is no such
// route" is a legitimate answer a caller has to be able to tell from "this path is the wrong one".
func MCPRouteForPath(path string) (MCPRouteInfo, bool) {
	pattern, _, ok := routeRiskFor(path)
	if !ok {
		return MCPRouteInfo{}, false
	}
	r, ok := manifest[pattern]
	if !ok {
		// routeRiskFor only ever returns a key it read from this map, so this is unreachable
		// unless the manifest were mutated concurrently, which nothing does.
		return MCPRouteInfo{}, false
	}
	return mcpRouteInfoOf(pattern, r), true
}

// MCPNeedsConfirm reports whether a risk class string is one the gate requires a confirmation for.
//
// Takes the string rather than the unexported type because that is what the MCP wire carries, and
// it resolves the string through this package's own needsConfirmation rather than restating the set:
// a second copy of "which classes are gated" would drift from the gate, and the drift would be a
// route that is confirmed or refused by the wrong rule.
func MCPNeedsConfirm(risk string) bool {
	return needsConfirmation(riskClass(risk))
}

// MCPMethodMutates reports whether a verb is one the confirmation gate can refuse for want of a
// token.
//
// Confirmation is demanded of mutating calls only — a GET on a gated route is a read of the state
// the gate protects, not the protected act. A transport that described the gate without this would
// have to restate which verbs those are, and a restatement is a second answer.
func MCPMethodMutates(method string) bool { return methodMutates(method) }

// MCPConfirmHeaderName is the request header a confirmation is spent through, and MCPConfirmMintPath
// is the path that mints one for a gated route.
const (
	// MCPConfirmHeaderName is ConfirmHeader, exported for the same reason the others are: a client
	// building a request should not have to guess the field name, which is the same reason every
	// other wire shape in this package is exported.
	MCPConfirmHeaderName = ConfirmHeader
	// MCPConfirmMintPath is the path that mints a one-time confirmation for a gated route, built
	// the way registerConfirmationRoutes builds it — trailing slash trimmed, then "/confirm" — so
	// the transport and the gate cannot disagree about where a token comes from.
	//
	// A subtree pattern is what the token is issued AGAINST, which is why this takes the manifest
	// pattern rather than a request path.
	MCPConfirmMintPath = "/confirm"
)

// MCPConfirmEndpoint returns the full path a confirmation for a route pattern is minted at, e.g.
// "/api/audit/confirm" for the "/api/audit/" subtree. TrimSuffix before appending mirrors
// registerConfirmationRoutes: without it a subtree pattern yields "//confirm", which ServeMux treats
// as a distinct path no caller types, i.e. a gated route whose mint endpoint is unreachable.
func MCPConfirmEndpoint(pattern string) string {
	return strings.TrimSuffix(pattern, "/") + MCPConfirmMintPath
}

// MCPConfirmTTLSeconds is how long a minted confirmation stays valid, as a number a caller can put
// in a message without formatting a duration.
func MCPConfirmTTLSeconds() int { return confirmTTLSeconds() }

// MCPGuarded returns the server's own request chain: the cross-site gate outside the
// unattended-caller confirmation gate outside the route mux (see setupRoutes).
//
// This accessor exists so an in-process caller is refused by the same gate a socket caller is. Two
// callers use it, and both go through the real chain rather than a copy of it, because a copy of the
// gate is not the gate: the MCP transport's tests mount it on an httptest server, and the mint
// endpoints are on the chain too (the gate consults confirmMux itself), so a confirmation minted and
// spent there is minted and spent by the same real confirmStore.
func (s *Server) MCPGuarded() http.Handler { return s.guarded }
