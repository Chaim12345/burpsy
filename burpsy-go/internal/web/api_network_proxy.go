package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// /api/network/proxy — the upstream proxy servers and SOCKS chain, Burp's two Network settings panels
// (configPanelUpstreamProxyServers and configPanelSocksProxy) as one route.
//
// # Why one route for both panels
//
// Burp splits them because its SOCKS proxy is a single global setting and its HTTP upstream proxies are
// a per-destination list — a split that costs Burp users the ability to send one host through SOCKS and
// another direct. Here the proxy kind is part of the rule, so `socks5://` and `http://` are two values
// of one field and the per-destination list covers both. One list, one resolution order, and no second
// place where a global setting can silently override the specific rule an operator wrote.
//
// # What the response reports that the policy alone cannot
//
// `attached` is the list of egress surfaces actually holding this policy object. It exists because the
// honest answer to "will this rule apply?" is not derivable from the rule: a rule reaches exactly the
// surfaces that hold the policy, and a process wired for senders but not for the proxy listener would
// otherwise present a settings panel that looks global and covers half the traffic. `wired: false` is
// the same honesty one level up — no policy at all, so an edit here would be accepted and consulted by
// nothing, and the handler refuses rather than storing it.
//
// # Credentials
//
// Supported, for both the HTTP kinds (Proxy-Authorization: Basic) and SOCKS5 (RFC 1929). A userinfo URL
// is therefore never silently ignored — except for socks4://, which has no password field on the wire
// at all and refuses the URL rather than authenticating as something the operator did not configure
// (see upstream.Parse). Nothing in this file can emit a password: the views below render
// upstream.Proxy.Display, which redacts, and `has_credentials` is how the panel shows that
// authentication is configured without the API ever serving the secret back.

// networkProxyRuleView is one rule as an operator sees it. `proxy` is the redacted form.
type networkProxyRuleView struct {
	Pattern string `json:"pattern"`
	// Proxy is Display(): scheme, host, port, and "***@" in place of any credentials.
	Proxy string `json:"proxy"`
	// Kind is the wire protocol, so the panel can badge socks5 differently from http without parsing
	// the display string back apart.
	Kind string `json:"kind"`
	// HasCredentials reports that a username is configured. The value is never served.
	HasCredentials bool `json:"has_credentials"`
	// Direct marks a rule that exempts its pattern from a broader default. Reported explicitly because
	// "direct" as a proxy string is easy to misread as "no rule".
	Direct bool `json:"direct"`
}

// networkCarrierView is the global SOCKS layer as the panel sees it.
type networkCarrierView struct {
	// Configured is false when no hop is installed, which is the state every surface is in until an
	// operator names one. It is distinct from Socks == "", which is the same state spelled differently.
	Configured bool `json:"configured"`
	// Socks is the hop's redacted address, or "" when none is installed. Read from the carrier's own
	// view rather than from the settings document, so the panel shows what is IN FORCE.
	Socks string `json:"socks"`
	// Bypass lists the destination host patterns that skip the hop.
	Bypass []string `json:"bypass"`
	// RemoteResolve asks the SOCKS server to resolve destination names, which is what makes an
	// internal-only hostname reachable through it. It is a SOCKS feature and is refused for an HTTP
	// hop rather than silently ignored.
	RemoteResolve bool `json:"remote_resolve"`
	// Attached is every egress surface holding this carrier, for the reason the policy's own Attached
	// field exists: a setting that only one surface honours looks global on screen and is not.
	Attached []string `json:"attached"`
	// Limits names what the carrier does NOT cover, in the operator's terms.
	//
	// It is reported rather than left in a code comment because a carrier that silently skips one
	// destination is a setting that looks complete and is not — the same overclaim the Attached field
	// exists to prevent, one level down. Today that is an HTTPS upstream proxy: crypto/tls calls
	// DialContext on the net.Dialer it is handed and Go's net.Dialer has no field a carrier can
	// replace, so the hop cannot be put underneath one without reimplementing the TLS dial
	// (burpsy-react-ui-mr83 part 3).
	Limits []string `json:"limits"`
}

// carrierUpdate is one edit to the global SOCKS layer.
type carrierUpdate struct {
	// Socks is the hop's address. Empty CLEARS the carrier, which is an operator removing the setting
	// and must land on a direct dial rather than on a hop to nowhere.
	Socks string `json:"socks"`
	// Bypass lists destination host patterns that skip the hop, in the same language a destination
	// rule uses: an exact name or `*.example.com`.
	Bypass []string `json:"bypass"`
	// RemoteResolve asks the SOCKS server to resolve destination names. Refused for an HTTP hop,
	// where the setting would be silently ignored.
	RemoteResolve bool `json:"remote_resolve"`
}

// applyCarrierUpdate installs a carrier edit, and reports rather than swallows a refusal: a bad SOCKS
// address or a remote-DNS request on an HTTP hop is the operator's mistake, and finding out when the
// first outbound connection hangs is much worse than being told now.
func (s *Server) applyCarrierUpdate(u carrierUpdate) error {
	if s.upstreamCarrier == nil {
		return fmt.Errorf("no carrier is wired into this process, so a layer stored here would be " +
			"consulted by nothing")
	}
	return s.upstreamCarrier.SetSocks(u.Socks, u.Bypass, u.RemoteResolve)
}

// networkProxyView is GET /api/network/proxy.
type networkProxyView struct {
	// Wired reports that a policy object exists for this process. False means every field below is a
	// description of nothing and a POST would be refused.
	Wired bool                   `json:"wired"`
	Rules []networkProxyRuleView `json:"rules"`
	// Default is the redacted proxy for destinations no rule matched, "direct" when there is none.
	Default string `json:"default"`
	// DefaultKind and DefaultHasCredentials mirror the per-rule fields for the default.
	DefaultKind           string `json:"default_kind"`
	DefaultHasCredentials bool   `json:"default_has_credentials"`
	// Empty distinguishes "no proxying configured" from "a policy whose rules all resolve to direct".
	// Two states that look identical in the rule table and mean different things.
	Empty bool `json:"empty"`
	// Attached is every egress surface holding this policy — "sender", "proxy", "web". See the file
	// comment: this is the field that keeps the panel from implying coverage it cannot see.
	Attached []string `json:"attached"`
	// Carrier is the global SOCKS layer: a TCP hop that EVERY outbound connection is opened through,
	// beneath whichever proxy a rule selected above. It is reported separately from the rules because
	// it is a different kind of thing — the rules answer "which proxy carries this host" and the carrier
	// answers "what opens the socket to reach that proxy" — and showing one without the other is how an
	// operator concludes the other is covered (burpsy-react-ui-mr83 part 3).
	Carrier networkCarrierView `json:"carrier"`
	// Persisted reports whether edits survive a restart. False when no -db was given, which is worth
	// saying next to a settings panel whose changes would otherwise silently be for this run only.
	Persisted bool `json:"persisted"`
	// CredentialsSupported is stated rather than assumed by the panel, so the UI's note about
	// authenticated proxies comes from the server that would have to honour it.
	CredentialsSupported bool `json:"credentials_supported"`
	// Schemes is what upstream.Parse accepts, so the panel's hint text cannot drift from the parser.
	Schemes []string `json:"schemes"`
}

// networkProxyUpdate is POST /api/network/proxy.
//
// Default is a pointer on purpose: an omitted field must leave the default alone, and only an
// explicitly sent "" or "direct" clears it. With a plain string the two are indistinguishable, and
// every rule-only edit would silently switch the default back to direct — turning a form submission
// into an un-proxying of everything no rule covers.
type networkProxyUpdate struct {
	Pattern string  `json:"pattern"`
	Proxy   string  `json:"proxy"`
	Default *string `json:"default"`
	// Carrier edits the global SOCKS layer, which is a different thing from the rules above: a rule
	// answers "which proxy carries this host" and a carrier answers "what opens the socket to reach
	// that proxy". A panel that showed one and not the other would let an operator conclude the other
	// is covered (burpsy-react-ui-mr83 part 3).
	Carrier *carrierUpdate `json:"carrier"`
}

func (s *Server) handleNetworkProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getNetworkProxy(w, r)
	case http.MethodPost:
		s.updateNetworkProxy(w, r)
	case http.MethodDelete:
		s.deleteNetworkProxyRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getNetworkProxy(w http.ResponseWriter, _ *http.Request) {
	s.writeNetworkProxy(w)
}

// writeNetworkProxy renders the whole view. Shared by the GET and by every POST, because a POST that
// answers with a partial acknowledgement is how a panel and a server come to disagree about what is
// in force — and the carrier's whole claim is that it is global.
func (s *Server) writeNetworkProxy(w http.ResponseWriter) {
	view := networkProxyView{
		Wired:                s.upstreamProxy != nil,
		Rules:                []networkProxyRuleView{},
		Default:              "direct",
		DefaultKind:          string(upstream.KindDirect),
		Empty:                true,
		Attached:             []string{},
		Persisted:            s.persist != nil,
		CredentialsSupported: true,
		// Named from the parser's own accepted set rather than retyped, so a scheme added there shows
		// up here and the panel cannot offer one the dial path cannot speak.
		Schemes: upstream.Schemes(),
	}
	// The carrier is read from its own object, never rebuilt from the settings document, so the panel
	// shows what is IN FORCE. A carrier that is wired but bypasses everything reads identically to one
	// that is not installed, and only the live object can tell them apart.
	if s.upstreamCarrier != nil {
		proxy, bypass, remote, configured := s.upstreamCarrier.Configured()
		view.Carrier = networkCarrierView{
			Configured:    configured,
			Socks:         proxy,
			Bypass:        bypass,
			RemoteResolve: remote,
			Attached:      s.upstreamCarrier.AttachedSurfaces(),
			Limits:        s.upstreamCarrier.Limits(),
		}
	}
	if s.upstreamProxy != nil {
		def := s.upstreamProxy.Default()
		view.Default = def.Display()
		view.DefaultKind = string(def.Kind())
		view.DefaultHasCredentials = def.HasCredentials()
		view.Empty = s.upstreamProxy.Empty()
		view.Attached = s.upstreamProxy.AttachedSurfaces()
		for _, rule := range s.upstreamProxy.Rules() {
			view.Rules = append(view.Rules, networkProxyRuleView{
				Pattern:        rule.Pattern,
				Proxy:          rule.Proxy.Display(),
				Kind:           string(rule.Proxy.Kind()),
				HasCredentials: rule.Proxy.HasCredentials(),
				Direct:         rule.Proxy.IsDirect(),
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// updateNetworkProxy upserts a rule and/or replaces the default.
//
// Refuse-by-default throughout: a proxy URL that does not parse answers 400 and nothing is stored. The
// alternative — accept the string and discover at dial time that it is unusable — would leave an
// operator looking at a configured rule while their traffic went straight to the target, which is the
// one outcome someone who configured a proxy did not ask for.
//
// The default is applied before the rule so a body carrying both leaves the policy in the state the
// operator described, rather than in one where a refused rule has already moved the default.
func (s *Server) updateNetworkProxy(w http.ResponseWriter, r *http.Request) {
	if s.upstreamProxy == nil {
		http.Error(w, "No upstream proxy policy is wired into this process, so a rule stored here would "+
			"be consulted by nothing", http.StatusServiceUnavailable)
		return
	}
	var req networkProxyUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	pattern := strings.TrimSpace(req.Pattern)
	if req.Default == nil && pattern == "" && req.Carrier == nil {
		http.Error(w, "Nothing to change: send a pattern with its proxy, a default, a carrier, or any of them",
			http.StatusBadRequest)
		return
	}
	// The carrier is applied FIRST and on its own, because it is a different layer from the rules: a
	// body that sets a valid carrier and an invalid rule must leave the carrier working. The reverse
	// order would leave an operator with neither, which for a body they believed they had saved is
	// the same silent failure as any other half-applied edit.
	if req.Carrier != nil {
		if err := s.applyCarrierUpdate(*req.Carrier); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Default == nil && pattern == "" {
		s.writeNetworkProxy(w)
		return
	}
	// Both arms are validated before either is applied, so a body with a good default and a bad rule
	// changes nothing at all. A half-applied proxy policy is the state an operator must not be left
	// silently holding — the same reason upstream.Policy.Restore refuses a partial restore.
	if req.Default != nil {
		if _, err := upstream.Parse(*req.Default); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if pattern != "" {
		if _, err := upstream.Parse(req.Proxy); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Default != nil {
		if err := s.upstreamProxy.SetDefault(*req.Default); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if pattern != "" {
		if _, err := s.upstreamProxy.Set(pattern, req.Proxy); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.persistUpstreamProxy()
	s.getNetworkProxy(w, r)
}

// deleteNetworkProxyRule removes one rule by exact pattern, or clears the whole policy.
//
// ?pattern= removes exactly that rule and answers 404 when no rule carries it. Exact, not "the rule
// that would match this host": a double-clicked remove must answer "no such rule" the second time
// rather than deleting a second, different rule that happens to cover the same hosts — which would
// make one click look like two rules had existed.
//
// ?all=true clears every rule and the default. Separate from the pattern arm rather than folded into an
// empty pattern, because "delete with no pattern" is what a UI bug sends and un-proxying everything is
// not a reasonable interpretation of it.
func (s *Server) deleteNetworkProxyRule(w http.ResponseWriter, r *http.Request) {
	if s.upstreamProxy == nil {
		http.Error(w, "No upstream proxy policy is wired into this process", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Query().Get("all") == "true" {
		s.upstreamProxy.Clear()
		s.persistUpstreamProxy()
		s.getNetworkProxy(w, r)
		return
	}
	pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
	if pattern == "" {
		http.Error(w, "A removal needs ?pattern=, or ?all=true to clear every rule", http.StatusBadRequest)
		return
	}
	if !s.upstreamProxy.Remove(pattern) {
		http.Error(w, fmt.Sprintf("No upstream proxy rule has the pattern %q", pattern), http.StatusNotFound)
		return
	}
	s.persistUpstreamProxy()
	s.getNetworkProxy(w, r)
}
