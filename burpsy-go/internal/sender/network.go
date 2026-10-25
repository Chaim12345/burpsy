package sender

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// NetworkSettings is the one named surface for the network decisions every sender in this process was
// previously making implicitly, each in its own place.
//
// # Why one struct rather than more SenderConfig fields
//
// Before this, "how long may a send take" had no single answer. The scanner carried a `timeout_ms` and
// a `probe_timeout_ms`, `SenderConfig.Timeout` stood in for connect, read and total at once, and the
// transport's TLSHandshakeTimeout and ExpectContinueTimeout were literals nobody could reach. An
// operator asking "why did that request give up after ten seconds" had four places to look and no way
// to change any of them. The three timeouts here are distinct because they fail differently: a connect
// timeout means the host is not there, a read timeout means it is there and silent, and a total
// timeout means the whole exchange overran — and an operator hunting a slow endpoint needs to raise one
// without raising the others.
//
// # What is deliberately absent
//
// There is no "verify TLS" arm and no proxy arm. Those already live on SenderConfig, and duplicating a
// knob is how the two copies come to disagree — the same defect SenderConfig's own doc comment records
// about a MaxRedirects nothing enforced.
type NetworkSettings struct {
	Resolution ResolutionSettings `json:"resolution"`
	Timeouts   TimeoutSettings    `json:"timeouts"`
	Redirects  RedirectSettings   `json:"redirects"`
	Continue   ContinueSettings   `json:"continue"`
	Streaming  StreamingSettings  `json:"streaming"`
	TLS        TLSSettings        `json:"tls"`
	// HTTP1 and HTTP2 are Burp's project-wide protocol defaults (burpsy-react-ui-ry5n), under Burp's
	// own key names (project_options.http.http1 / http2). Pointers because a settings document written
	// before they existed is unmarshalled onto a zero struct, and the zero value of HTTP2 would turn
	// h2 off for every send: nil means Burp's default, which is keep-alive off and h2 on.
	HTTP1 *HTTP1Settings `json:"http1,omitempty"`
	HTTP2 *HTTP2Settings `json:"http2,omitempty"`
	// HTTP3 is burpsy's own panel - Burp speaks no h3. Pointer for the same reason as HTTP1/HTTP2:
	// a document written before it existed unmarshals nil, and nil must mean the default (the
	// Alt-Svc leg ON, vln3 ruling C), which a zero struct would read as off.
	HTTP3 *HTTP3Settings `json:"http3,omitempty"`
}

// HTTP1Settings is Burp's "HTTP/1" panel.
type HTTP1Settings struct {
	// EnableKeepAlive is "Use keep-alive for HTTP/1 if the server supports it". See keepalive.go.
	EnableKeepAlive bool `json:"enable_keep_alive"`
}

// HTTP2Settings is Burp's "HTTP/2" panel.
type HTTP2Settings struct {
	// EnableHTTP2 is "Default to HTTP/2 if the server supports it". Off, a send that names no protocol
	// goes out as HTTP/1.1 whatever the target negotiates; a request written as HTTP/2, or pinned to
	// h2 by its caller, still rides h2, as Burp's per-request protocol toggle overrides this default.
	EnableHTTP2 bool `json:"enable_http2"`
}

// KeepAliveHTTP1 reports whether HTTP/1 connections are kept for reuse.
func (n NetworkSettings) KeepAliveHTTP1() bool { return n.HTTP1 != nil && n.HTTP1.EnableKeepAlive }

// DefaultToHTTP2 reports whether a send that names no protocol may use h2.
func (n NetworkSettings) DefaultToHTTP2() bool { return n.HTTP2 == nil || n.HTTP2.EnableHTTP2 }

// HTTP3Settings is burpsy's own "HTTP/3" panel (burpsy-react-ui-kidb); Burp has no equivalent.
type HTTP3Settings struct {
	// EnableHTTP3AltSvc governs the proxy's Alt-Svc leg: when on (the default), forwarded
	// responses teach the proxy which origins advertise HTTP/3 and later forwards to those
	// origins may ride QUIC, disclosed on the exchange row (vln3). Off makes the leg inert:
	// nothing learned, nothing ridden. Operator-explicit h3 pins (0hgx phase 1) are unaffected -
	// the switch governs discovery, not an explicit instruction.
	EnableHTTP3AltSvc bool `json:"enable_http3_alt_svc"`
}

// RideHTTP3AltSvc reports whether the proxy's Alt-Svc leg is live. Default ON.
func (n NetworkSettings) RideHTTP3AltSvc() bool { return n.HTTP3 == nil || n.HTTP3.EnableHTTP3AltSvc }

// TLSSettings is how the operator governs the certificate the TARGET presents.
//
// # Why it lives here rather than only on SenderConfig
//
// SenderConfig.TLSVerify has governed the sender's own egress leg since the codecs landed, but it is a
// construction-time field with no settings surface behind it: an operator could not see it, could not
// change it while running, and the proxy leg had no equivalent at all — every intercepted connection
// was opened with verification off and nothing anywhere could say so (burpsy-react-ui-f365).
//
// Putting it in NetworkSettings gives it the same live, persisted, API-edited life as every other
// network decision, and lets the same edit reach the sender and the proxy. The field is the SAME
// setting, not a second one: an operator who turns verification off means it for every leg, and two
// knobs that could disagree would be the overclaim this section exists to remove.
//
// Verify defaults to true, which is Burp's default and the only safe reading of a field whose absence
// would otherwise mean "accept anything".
type TLSSettings struct {
	// Verify is whether the target's certificate is verified. True by default; false is the
	// deliberate opt-out for a self-signed target, and it is the setting an assessor reaches for
	// rather than one burpsy should choose on their behalf.
	Verify bool `json:"verify"`
	// RootCAPath is a PEM bundle added to the system pool for verification. Empty means the system
	// pool alone. It is how an operator reaches a target whose issuer is private without giving up
	// verification entirely.
	RootCAPath string `json:"root_ca_path"`
	// MinVersion is the lowest TLS version accepted, as Burp's protocol selection expresses it. Zero
	// means Go's default, which is the floor Go considers safe.
	MinVersion uint16 `json:"min_version"`
}

// ResolutionPolicy names where a hostname's address comes from.
type ResolutionPolicy string

const (
	// ResolutionSystem uses the host's own resolver — whatever /etc/resolv.conf, systemd-resolved or
	// the platform API says. The default, because it is what every other tool on the machine sees.
	ResolutionSystem ResolutionPolicy = "system"
	// ResolutionResolver sends queries to one named resolver instead. For an engagement whose targets
	// only resolve inside a client's split-horizon DNS, where the operator has the resolver's address
	// but cannot reconfigure the machine.
	ResolutionResolver ResolutionPolicy = "resolver"
)

// HostOverride maps one hostname onto a literal address, so a request can be sent to a host that DNS
// does not point at — a pre-cutover deployment, a service reachable only by IP, a vhost being tested
// before its record exists.
//
// # The SNI and Host header keep the name
//
// The override changes only the address dialled. The TLS ServerName and the Host header stay the
// hostname the operator named, because the point of the override is to reach a *named* vhost at an
// address of the operator's choosing: rewriting the name too would test whatever the address serves
// by default, which is a different question and usually the wrong one. This is why sender's TLS dial
// takes serverName and addr as two arguments rather than deriving one from the other.
type HostOverride struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

// ResolutionSettings is the hostname-resolution table plus the lookup policy.
type ResolutionSettings struct {
	// Overrides is consulted before any resolver is. First enabled match on an exact,
	// case-insensitive hostname wins.
	Overrides []HostOverride   `json:"overrides"`
	Policy    ResolutionPolicy `json:"policy"`
	// Resolver is the address queries go to under ResolutionResolver. A bare address takes port 53.
	Resolver string `json:"resolver"`
	// TimeoutMS bounds one lookup. Zero means the resolver's own default.
	TimeoutMS int `json:"timeout_ms"`
	// Family is the address family the answer is filtered to, which is Burp's resolution-address
	// preference (settings/network/dns.html:49-65): "because routing restrictions may permit only one
	// family". ResolutionSystem is the default and returns the resolver's order untouched.
	Family AddressFamily `json:"family"`
	// Lookup is the name-resolution seam the family preference resolves through. Nil means the
	// configured resolver, or the system one.
	//
	// It exists because the preference's whole job is choosing between two families, and a machine
	// that resolves only one of them cannot demonstrate the choice: localhost is IPv4-only on most
	// boxes, so a test that used it passed whether or not the transport honoured the setting. A test
	// that answers for both families can, and a real resolver cannot be asked for both on demand.
	//
	// Not part of the wire shape — it has no json tag and no key, so a settings document cannot set
	// it. It is a seam, not a setting, and the only writer is a test.
	Lookup func(ctx context.Context, host string) ([]string, error) `json:"-"`
}

// AddressFamily is which family a hostname's answer is filtered to.
type AddressFamily string

const (
	// FamilySystem leaves the resolver's ordering alone, which is what every dial did before the
	// preference existed. The default because the system order encodes the operator's own routing
	// preferences, and overriding them is a decision they have to make.
	FamilySystem AddressFamily = "system"
	// FamilyIPv4 keeps only A records.
	FamilyIPv4 AddressFamily = "ipv4"
	// FamilyIPv6 keeps only AAAA records. A dual-stack target reachable only over IPv6 is the shape
	// this exists for; a target reachable over NEITHER is refused, which is the honest outcome.
	FamilyIPv6 AddressFamily = "ipv6"
)

// familyValue is the Go constant a family names, and whether the family is a filter at all. System is
// not a filter: it means the resolver's own order, and returning its answer untouched is the whole
// point rather than a special case of preferring one family.
func (f AddressFamily) familyValue() (uint32, bool) {
	switch f {
	case FamilyIPv4:
		return 4, true
	case FamilyIPv6:
		return 6, true
	default:
		return 0, false
	}
}

// String names the family for the settings document and a refusal message.
func (f AddressFamily) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "system"
	}
}

// filterFamily returns the addresses of one family from a resolver's answer, in the resolver's order.
//
// It is a filter over an existing answer set rather than a resolver rewrite, for a reason that is
// about correctness rather than taste: a per-family query (AAAA rather than A) can be answered
// differently by a split-horizon resolver than a filtered answer to a question the operator actually
// asked, and the engagement's own DNS is the thing that knows. RFC 6555's "filtered AAAA" exists for
// deployments that want it; a security tool should not be one by default.
func filterFamily(addrs []string, family AddressFamily) ([]string, bool) {
	want, ok := family.familyValue()
	if !ok {
		return addrs, true
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			// A literal that is not an IP, or something the resolver returned that is neither, is kept
			// out: this function filters to one family and an unparseable answer is not of either.
			continue
		}
		if ip.To4() != nil {
			if want == 4 {
				out = append(out, addr)
			}
			continue
		}
		if want == 6 {
			out = append(out, addr)
		}
	}
	return out, len(out) > 0
}

// resolutionFailure names why a hostname could not be turned into a dialable address, and is what a
// caller reports when the family filter found nothing.
//
// "no address of that family" is the whole reason this is a separate type rather than an empty list: a
// dual-stack host with only an IPv6 route, asked for IPv4, is a routing problem the operator has to
// see. A generic "could not resolve" would read as a DNS fault and send them to the wrong setting.
type resolutionFailure struct {
	host   string
	family AddressFamily
	empty  bool
}

func (e *resolutionFailure) Error() string {
	if e.empty {
		return "resolution.family is " + e.family.String() + " and " + e.host +
			" has no address of that family; a host reachable over the other family only cannot be " +
			"dialled, and setting resolution.family to system would return both"
	}
	return "resolution found no usable address for " + e.host
}

// resolveForDial turns a hostname into one address to dial, applying the override table and then the
// family preference.
//
// # Why it resolves rather than handing the name to the dialer
//
// net.Dialer takes a hostname and does this work itself, but it also does it the OPERATOR's platform
// way: it walks the resolver's answers and connects to the first that opens, and on a dual-stack host
// whose AAAA is unroutable it may try the AAAA, wait out the connect timeout, and only then try the A.
// The result is a request that takes the connect timeout to fail on a host that was reachable all
// along, which is the shape burpsy-react-ui-mr83 part 2 records: an operator with no setting that
// fixes it, who must override the hostname one address at a time.
func (n NetworkSettings) resolveForDial(ctx context.Context, host string) (string, error) {
	if addr, ok := n.Resolution.resolveHost(host); ok {
		// An override is an operator naming one address. The family preference does not second-guess
		// it: they said this address, and a filter here would silently discard the address they typed
		// and dial somewhere they did not ask for.
		return addr, nil
	}
	if _, isFilter := n.Resolution.Family.familyValue(); !isFilter {
		return host, nil
	}

	// Only the filtering path needs to resolve here; the system path hands the hostname to the dialer
	// exactly as it always did.
	candidates, err := n.Resolution.lookup(ctx, host)
	if err != nil {
		return "", &resolutionFailure{host: host, family: n.Resolution.Family}
	}
	filtered, ok := filterFamily(candidates, n.Resolution.Family)
	if !ok {
		return "", &resolutionFailure{host: host, family: n.Resolution.Family, empty: true}
	}
	return filtered[0], nil
}

// TimeoutSettings splits what SenderConfig.Timeout used to conflate.
type TimeoutSettings struct {
	// ConnectMS bounds the TCP connect and the TLS handshake. Zero means no bound of its own.
	ConnectMS int `json:"connect_ms"`
	// ReadMS bounds the wait for a response to begin arriving. Zero means no bound of its own.
	ReadMS int `json:"read_ms"`
	// TotalMS bounds one whole exchange, dial through last body byte. Zero means unbounded, which is
	// only sane when the caller supplies a context deadline instead.
	TotalMS int `json:"total_ms"`
}

// RedirectMode is Burp's four-way redirect policy.
type RedirectMode string

const (
	// RedirectNever returns the 30x as the response it is. The default, and what every sender in this
	// process did before there was a policy at all.
	RedirectNever RedirectMode = "never"
	// RedirectOnSite follows a hop only when it names the same scheme, host and port.
	RedirectOnSite RedirectMode = "on_site"
	// RedirectInScope follows a hop the engagement scope authorises, on any authority.
	RedirectInScope RedirectMode = "in_scope"
	// RedirectAlways follows any hop the scope authorises.
	//
	// # This is not Burp's "always", and the difference is deliberate
	//
	// Burp's "always" follows a Location anywhere. Ours cannot, because a redirect hop here is sent
	// through a sender.AuthorisedSender bound to the new authority, and that gate is what makes a hop
	// a hop rather than an ungated dial. So "always" here means "do not apply an additional on-site or
	// scope-shaped filter of my own" — the scope still decides, as it decides about every other byte
	// this tool sends. A mode that could send a request the scope refuses would not be a feature; it
	// would be the "hostile target steers you at an internal service" escape with a settings entry in
	// front of it. RedirectInScope and RedirectAlways therefore differ only in what they report: the
	// in-scope mode says a filtered hop was filtered by policy, the always mode says it was refused by
	// scope. The set of requests actually sent is the same, and the UI says so.
	RedirectAlways RedirectMode = "always"
)

// RedirectSettings is the opt-in redirect policy.
//
// Off by default, and that is a design position rather than an oversight — see FollowRedirects in
// redirect.go for why following inside the transport is the thing that stays impossible.
type RedirectSettings struct {
	Mode RedirectMode `json:"mode"`
	// MaxHops bounds a chain. A redirect loop is the ordinary case, not the exotic one.
	MaxHops int `json:"max_hops"`
	// ReplayCookies makes a followed chain resubmit the cookies each hop's response set, to that
	// hop's OWN authority. Burp exposes it as "Follow redirections and resubmit cookies"
	// (settings/tools/repeater.html:143-145), and it is what makes a login or SSO flow that sets a
	// cookie on a 302 work at all.
	//
	// Default OFF, unlike a browser's. burpsy sends what an operator wrote, and a cookie the target
	// set mid-chain is not something they asked to send — a chain that suddenly carries a credential
	// nobody typed is the surprise this setting exists to let an operator turn off. A target that sets
	// throwaway cookies is the other reason: without a switch, following its redirects would keep
	// resending them.
	ReplayCookies bool `json:"replay_cookies"`
	// Types is Burp's "Allowed redirect types" (project_options.http.redirections, burpsy-react-ui-z9zi):
	// which kinds of response count as a redirect to follow. nil means Burp's defaults (3xx with
	// Location, the Refresh header and the meta refresh tag; not any status with a Location, not
	// JavaScript), so a settings document written before this existed behaves as Burp does. A pointer
	// because the zero value of the struct would be "follow nothing".
	Types *RedirectTypes `json:"types,omitempty"`
	// CrossDomainProtocol is the protocol a hop to ANOTHER host must use (burpsy-react-ui-adkx —
	// Burp's "Use selected protocol for cross-domain redirects" / "Enforce protocol choice on
	// cross-domain redirections"). ProtocolPreferenceAuto, the zero value and Burp's default, lets
	// each hop negotiate as normal. A per-send choice, never a stored setting: it is not serialised,
	// so a network-settings document can neither carry nor persist it.
	CrossDomainProtocol ProtocolPreference `json:"-"`
}

// RedirectTypes are Burp's five redirect kinds, under Burp's own key names.
type RedirectTypes struct {
	Understand3xx           bool `json:"understand_3xx_status_code"`
	UnderstandAnyLocation   bool `json:"understand_any_status_code_with_location_header"`
	UnderstandRefreshHeader bool `json:"understand_refresh_header"`
	UnderstandMetaRefresh   bool `json:"understand_meta_refresh_tag"`
	// UnderstandJavaScript is accepted only as false: following a JavaScript-driven redirect means
	// executing the page's script, which the sender does not do. Setting it true is refused by name
	// rather than stored as a promise nothing keeps.
	UnderstandJavaScript bool `json:"understand_javascript_driven"`
}

// DefaultRedirectTypes is Burp's shipped default (Preferences/ProjectDefaults.json).
func DefaultRedirectTypes() RedirectTypes {
	return RedirectTypes{Understand3xx: true, UnderstandRefreshHeader: true, UnderstandMetaRefresh: true}
}

// EffectiveTypes is the redirect types in force: the configured ones, or Burp's defaults.
func (r RedirectSettings) EffectiveTypes() RedirectTypes {
	if r.Types == nil {
		return DefaultRedirectTypes()
	}
	return *r.Types
}

// ContinueSettings makes the 100-continue handling explicit.
//
// Both arms describe behaviour that already existed and could not be seen or changed: the raw read
// path returned a bare `100 Continue` to its caller as though that were the response (it is an interim
// status; the response is the one after it), and the typed transport carried a one-second
// ExpectContinueTimeout literal.
type ContinueSettings struct {
	// Understand100 makes the raw read path skip 1xx interim responses and return the final one.
	// A 101 is never skipped — it is an upgrade, and the bytes after it belong to another protocol.
	Understand100 bool `json:"understand_100_continue"`
	// RemoveExpect strips `Expect: 100-continue` from outbound requests. For a peer that stalls on it
	// rather than answering, which is common enough that Burp offers the same switch.
	RemoveExpect bool `json:"remove_expect_header"`
	// ExpectTimeoutMS is how long the typed transport waits for a 100 before sending the body anyway.
	ExpectTimeoutMS int `json:"expect_continue_timeout_ms"`
}

// StreamingSettings names the hosts whose responses do not end.
//
// An event stream, a long-poll, a `text/event-stream` dashboard: the framing rule for these is "read
// until the peer closes", and the peer does not intend to. Before this they were indistinguishable
// from a hung target — the read deadline fired and the whole response, head included, came back as an
// error. Declaring the host instead bounds the read by its own knob and returns what arrived.
type StreamingSettings struct {
	// Hosts is matched case-insensitively against the authority's hostname, either exactly or as a
	// `*.example.com` suffix pattern.
	Hosts []string `json:"hosts"`
	// TimeoutMS is how long to keep reading a streaming response before returning what has arrived.
	// Burp calls this the open-ended response timeout.
	TimeoutMS int `json:"timeout_ms"`

	// The three response-handling switches, Burp's streaming_responses.* keys. They govern what the
	// proxy does with a response once it is recognised as streaming, and the proxy leg reads them off
	// this document (api_network pushes them into proxy.StreamingPolicy).

	// Store is "Store streaming responses (may result in large temp files)". A pointer, not a bare
	// bool, so a document that predates this field decodes to nil whatever struct it is decoded onto
	// (LoadNetworkSettings now decodes onto DefaultNetworkSettings, but other callers decode onto a
	// zero struct). Nil means the shipped default, which StoreStreamed reads as on.
	Store *bool `json:"store,omitempty"`
	// StripChunkedMetadata is "Strip chunked encoding metadata from streamed responses". Defaults off,
	// which reproduces forwarding a streamed response exactly as it arrived.
	StripChunkedMetadata bool `json:"strip_chunked_encoding_metadata"`
	// UseTextEventStreamHeader is "Treat text/event-stream responses as streaming". Defaults off: a
	// framed text/event-stream response takes the buffered path like any other framed response until
	// the operator turns this on.
	UseTextEventStreamHeader bool `json:"use_text_event_stream_header"`
}

// StoreStreamed reads the Store switch, defaulting a nil (never-set, or loaded from a document that
// predates the field) to on — the behaviour that shipped before the switch existed, where every
// streamed response was recorded.
func (s StreamingSettings) StoreStreamed() bool {
	return s.Store == nil || *s.Store
}

// Bounds on what the API will accept. Stated as constants so a refusal message can name the limit
// rather than repeating a literal the reader has to trust.
const (
	// MaxTimeoutMS is twenty minutes. Long enough for the slowest legitimate audit request, short
	// enough that a mistyped value cannot wedge a sender until the process is killed.
	MaxTimeoutMS = 20 * 60 * 1000
	// MaxRedirectHops bounds a chain even if the operator asks for more. Burp's own default is 10.
	MaxRedirectHops = 20
	// MaxHostOverrides bounds the resolution table. Generous for a hand-maintained table; bounded so
	// a paste cannot make every dial walk a list of thousands.
	MaxHostOverrides = 512
	// MaxStreamingHosts bounds the streaming list, for the same reason.
	MaxStreamingHosts = 512
)

// DefaultNetworkSettings is what a process with no persisted settings behaves as, and it is chosen to
// be exactly the behaviour that shipped before these settings existed.
//
// That is the whole point: adding a settings surface must not change what the tool does. Redirects
// stay off, resolution stays with the system, and the three timeouts reproduce the values the code
// previously carried as literals — 30s total from DefaultSenderConfig, 10s connect from the
// transport's TLSHandshakeTimeout, 1s expect-continue from the transport. An operator who never opens
// the panel gets the tool they had.
func DefaultNetworkSettings() NetworkSettings {
	return NetworkSettings{
		Resolution: ResolutionSettings{
			Overrides: nil,
			Policy:    ResolutionSystem,
			TimeoutMS: 5_000,
		},
		Timeouts: TimeoutSettings{
			ConnectMS: 10_000,
			ReadMS:    0,
			TotalMS:   30_000,
		},
		Redirects: RedirectSettings{
			Mode:    RedirectNever,
			MaxHops: 5,
		},
		Continue: ContinueSettings{
			Understand100:   true,
			RemoveExpect:    false,
			ExpectTimeoutMS: 1_000,
		},
		Streaming: StreamingSettings{
			Hosts:     nil,
			TimeoutMS: 10_000,
		},
		// Verify ON. This is the default that matters most in the whole settings document: the
		// alternative is a tool that accepts any certificate from any target and says nothing, which is
		// the state burpsy-react-ui-f365 found the proxy permanently in.
		TLS: TLSSettings{Verify: true},
	}
}

// Validate refuses settings that cannot be applied, naming the field and the value.
//
// Refuse-by-default on unparseable input, the same rule the scope gate follows: an override whose
// address is not an address must not be silently dropped, because a dropped override means the request
// went to whatever DNS said instead — the one outcome the operator who typed it did not ask for.
func (n NetworkSettings) Validate() error {
	if err := n.Resolution.validate(); err != nil {
		return err
	}
	if err := n.Timeouts.validate(); err != nil {
		return err
	}
	if err := n.Redirects.validate(); err != nil {
		return err
	}
	if err := n.Continue.validate(); err != nil {
		return err
	}
	if err := n.Streaming.validate(); err != nil {
		return err
	}
	return n.TLS.validate()
}

// validate refuses a TLS policy that cannot be applied, naming the field and the value.
//
// The min-version floor is the only check: there is no such thing as a TLS version below 1.0, and a
// number claiming to be one is a corrupted document rather than a policy. The custom CA's CONTENTS are
// not checked here — the path is read by whichever leg dials, and a bundle that turns out malformed is
// reported at that handshake naming the path that produced it, which is the thing the operator has to
// fix. Refusing the whole document because a file is temporarily unreadable would leave no way to save
// an unrelated setting.
func (t TLSSettings) validate() error {
	if t.MinVersion != 0 && t.MinVersion < tls.VersionTLS10 {
		return fmt.Errorf("tls.min_version is 0x%04x, which is below TLS 1.0: there is no protocol below "+
			"it to select", t.MinVersion)
	}
	return nil
}

func (r ResolutionSettings) validate() error {
	switch r.Policy {
	case ResolutionSystem, ResolutionResolver:
	default:
		return fmt.Errorf("resolution.policy is %q, and the only lookup policies are %q and %q",
			r.Policy, ResolutionSystem, ResolutionResolver)
	}
	switch r.Family {
	case "", FamilySystem, FamilyIPv4, FamilyIPv6:
	default:
		return fmt.Errorf("resolution.family is %q, and the only preferences are %q, %q and %q",
			r.Family, FamilySystem, FamilyIPv4, FamilyIPv6)
	}
	if r.Policy == ResolutionResolver {
		if strings.TrimSpace(r.Resolver) == "" {
			return fmt.Errorf("resolution.policy is %q but resolution.resolver names no address to query",
				ResolutionResolver)
		}
		if _, err := normaliseResolver(r.Resolver); err != nil {
			return fmt.Errorf("resolution.resolver %q: %w", r.Resolver, err)
		}
	}
	if len(r.Overrides) > MaxHostOverrides {
		return fmt.Errorf("resolution.overrides holds %d entries, more than the %d allowed",
			len(r.Overrides), MaxHostOverrides)
	}
	seen := make(map[string]struct{}, len(r.Overrides))
	for i, o := range r.Overrides {
		host := strings.ToLower(strings.TrimSpace(o.Host))
		if host == "" {
			return fmt.Errorf("resolution.overrides[%d] names no host", i)
		}
		if strings.ContainsAny(host, "/:*? ") {
			return fmt.Errorf("resolution.overrides[%d] host %q is not a hostname: an override maps one "+
				"exact name onto one address, with no scheme, port, path or wildcard", i, o.Host)
		}
		if _, dup := seen[host]; dup {
			return fmt.Errorf("resolution.overrides[%d] repeats host %q, and two addresses for one name "+
				"would make which one is used depend on list order", i, o.Host)
		}
		seen[host] = struct{}{}
		addr := strings.TrimSpace(o.Address)
		if addr == "" {
			return fmt.Errorf("resolution.overrides[%d] (%s) names no address", i, o.Host)
		}
		if net.ParseIP(addr) == nil {
			return fmt.Errorf("resolution.overrides[%d] (%s) address %q is not an IP address: an override "+
				"replaces the lookup, so it has to end at an address rather than at another name",
				i, o.Host, o.Address)
		}
	}
	return boundedTimeout("resolution.timeout_ms", r.TimeoutMS)
}

func (t TimeoutSettings) validate() error {
	if err := boundedTimeout("timeouts.connect_ms", t.ConnectMS); err != nil {
		return err
	}
	if err := boundedTimeout("timeouts.read_ms", t.ReadMS); err != nil {
		return err
	}
	if err := boundedTimeout("timeouts.total_ms", t.TotalMS); err != nil {
		return err
	}
	// A total shorter than the connect bound cannot be honoured as written: the dial alone may use the
	// whole budget. Refused rather than clamped, because silently raising one of two numbers the
	// operator typed makes the panel lie about which bound is in force.
	if t.TotalMS > 0 && t.ConnectMS > t.TotalMS {
		return fmt.Errorf("timeouts.connect_ms (%d) is longer than timeouts.total_ms (%d), so the total "+
			"could expire during the dial and the read bound would never apply", t.ConnectMS, t.TotalMS)
	}
	if t.TotalMS > 0 && t.ReadMS > t.TotalMS {
		return fmt.Errorf("timeouts.read_ms (%d) is longer than timeouts.total_ms (%d), so the read bound "+
			"could never be reached", t.ReadMS, t.TotalMS)
	}
	return nil
}

func (r RedirectSettings) validate() error {
	switch r.Mode {
	case RedirectNever, RedirectOnSite, RedirectInScope, RedirectAlways:
	default:
		return fmt.Errorf("redirects.mode is %q, and the only modes are %q, %q, %q and %q",
			r.Mode, RedirectNever, RedirectOnSite, RedirectInScope, RedirectAlways)
	}
	if r.MaxHops < 0 || r.MaxHops > MaxRedirectHops {
		return fmt.Errorf("redirects.max_hops is %d, and a chain is bounded to between 0 and %d hops",
			r.MaxHops, MaxRedirectHops)
	}
	if r.Types != nil && r.Types.UnderstandJavaScript {
		return fmt.Errorf("redirects.types.understand_javascript_driven cannot be true: following a " +
			"JavaScript-driven redirect means executing the page's script, which this sender does not do")
	}
	if r.Mode != RedirectNever && r.MaxHops == 0 {
		return fmt.Errorf("redirects.mode is %q but redirects.max_hops is 0, which follows nothing: "+
			"say %q to mean that", r.Mode, RedirectNever)
	}
	return nil
}

func (c ContinueSettings) validate() error {
	return boundedTimeout("continue.expect_continue_timeout_ms", c.ExpectTimeoutMS)
}

func (s StreamingSettings) validate() error {
	if len(s.Hosts) > MaxStreamingHosts {
		return fmt.Errorf("streaming.hosts holds %d entries, more than the %d allowed",
			len(s.Hosts), MaxStreamingHosts)
	}
	for i, h := range s.Hosts {
		trimmed := strings.TrimSpace(h)
		if trimmed == "" {
			return fmt.Errorf("streaming.hosts[%d] is empty, and an empty pattern would match every host", i)
		}
		if strings.ContainsAny(trimmed, "/: ") {
			return fmt.Errorf("streaming.hosts[%d] %q is not a host pattern: give a hostname or a "+
				"*.example.com suffix, with no scheme, port or path", i, h)
		}
	}
	return boundedTimeout("streaming.timeout_ms", s.TimeoutMS)
}

func boundedTimeout(field string, ms int) error {
	if ms < 0 {
		return fmt.Errorf("%s is %d, and a timeout cannot be negative", field, ms)
	}
	if ms > MaxTimeoutMS {
		return fmt.Errorf("%s is %d, longer than the %d ms this tool will wait", field, ms, MaxTimeoutMS)
	}
	return nil
}

// Normalise returns the settings as they will actually be used: whitespace trimmed, hostnames
// lowercased, empty enum arms filled with their defaults.
//
// Called on the way in from the API and on the way out of persistence, so what the panel shows and
// what the dial path reads are the same values. A normalising step that only ran on one side is how a
// table displays `Example.COM ` and fails to match `example.com`.
func (n NetworkSettings) Normalise() NetworkSettings {
	out := n
	if out.Resolution.Policy == "" {
		out.Resolution.Policy = ResolutionSystem
	}
	out.Resolution.Resolver = strings.TrimSpace(out.Resolution.Resolver)
	overrides := make([]HostOverride, 0, len(out.Resolution.Overrides))
	for _, o := range out.Resolution.Overrides {
		overrides = append(overrides, HostOverride{
			Host:    strings.ToLower(strings.TrimSpace(o.Host)),
			Address: strings.TrimSpace(o.Address),
			Enabled: o.Enabled,
		})
	}
	if len(overrides) == 0 {
		overrides = nil
	}
	out.Resolution.Overrides = overrides

	// The CA path is trimmed like every other free-text field, so a path pasted with a trailing
	// newline does not become a file that does not exist. The value is otherwise untouched: a path the
	// operator cannot reach is reported by the leg that tries to read it, naming the path.
	out.TLS.RootCAPath = strings.TrimSpace(out.TLS.RootCAPath)

	// An absent family is the system default, NOT an empty filter. Normalising it here is what keeps
	// a settings document written before the field existed from resolving to nothing at all — the
	// failure mode of a string-typed enum whose zero value is not a valid member.
	if out.Resolution.Family == "" {
		out.Resolution.Family = FamilySystem
	}

	if out.Redirects.Mode == "" {
		out.Redirects.Mode = RedirectNever
	}
	if out.Redirects.MaxHops == 0 && out.Redirects.Mode != RedirectNever {
		out.Redirects.MaxHops = DefaultNetworkSettings().Redirects.MaxHops
	}

	hosts := make([]string, 0, len(out.Streaming.Hosts))
	for _, h := range out.Streaming.Hosts {
		if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	if len(hosts) == 0 {
		hosts = nil
	}
	out.Streaming.Hosts = hosts
	return out
}

// resolveHost returns the address an override maps host onto, and whether one applied.
//
// Exact, case-insensitive match on the hostname only. Deliberately not a pattern match: a wildcard
// override would mean one address serving a whole subtree of names, and the operator who wrote
// `*.example.com -> 10.0.0.1` almost certainly did not mean to send every host under that domain to
// one box. Scope patterns are the place for wildcards; an address table is not.
// DialAddress maps a host:port to the address this leg should actually dial, applying the
// hostname overrides and then the address-family policy (burpsy-react-ui-o1eu).
//
// Exported so the proxy listener resolves a host exactly as this package's own sends do — one
// implementation, so a split-horizon override cannot apply to Repeater and silently not to the
// traffic the operator is driving through the proxy, which is the leg they are most likely to be
// watching. An unparseable or unresolved address is returned as the caller built it: inventing one
// would dial an address nobody named.
func (r ResolutionSettings) DialAddress(ctx context.Context, host string, port uint16) string {
	if replacement, ok := r.resolveHost(host); ok {
		return net.JoinHostPort(replacement, strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func (r ResolutionSettings) resolveHost(host string) (string, bool) {
	needle := strings.ToLower(host)
	for _, o := range r.Overrides {
		if o.Enabled && o.Host == needle {
			return o.Address, true
		}
	}
	return "", false
}

// dialAddress is dialAddressFor with no context, for the callers that have none — the override
// table's own tests, and anywhere the family preference is already the system one and cannot need a
// lookup. It resolves against a background context, so a real send should prefer dialAddressFor.
func (n NetworkSettings) dialAddress(host string, port uint16) string {
	return n.dialAddressFor(context.Background(), host, port)
}

// dialAddressFor is the address a dial to host:port should actually use, after the override table and
// then the family preference.
//
// The family filter needs a resolver answer, which needs a context, so this takes one. The system
// preference — the default — does no lookup at all and returns the hostname unchanged, so the ordinary
// send is not paying for a resolution the dialer is about to do anyway.
// DialAddress is DialAddressFor, exported so another egress surface (the proxy listener) can
// apply the same resolution overrides and address-family policy this package's own sends do
// (burpsy-react-ui-o1eu). One implementation, so the two legs cannot resolve a host differently.
func (n NetworkSettings) DialAddress(ctx context.Context, host string, port uint16) string {
	return n.dialAddressFor(ctx, host, port)
}

func (n NetworkSettings) dialAddressFor(ctx context.Context, host string, port uint16) string {
	addr, err := n.resolveForDial(ctx, host)
	if err != nil || addr == "" {
		// A family filter that matched nothing resolves to the HOSTNAME, which then fails at the dial
		// with the operating system's own error. resolveForDial's message is the useful one, so it is
		// logged by the caller that can see it; here the address is simply not a rewrite, because
		// inventing one would dial an address nobody named.
		return net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}

// overrideAddr rewrites a `host:port` string the way dialAddress rewrites a host and a port, for the
// one caller that is handed an address rather than its parts: http.Transport's DialContext.
//
// An address it cannot split is returned unchanged rather than refused. This is not a scope decision —
// the transport is dialling a URL that AuthorisedSender already authorised, and the only thing being
// decided here is whether an override applies. Failing the dial over an address this function cannot
// parse would break sends that have nothing to do with the override table.
func (n NetworkSettings) overrideAddr(addr string) string {
	if len(n.Resolution.Overrides) == 0 {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if replacement, ok := n.Resolution.resolveHost(host); ok {
		return net.JoinHostPort(replacement, port)
	}
	return addr
}

// isStreaming reports whether host's responses are declared open-ended.
func (s StreamingSettings) isStreaming(host string) bool {
	needle := strings.ToLower(host)
	for _, pattern := range s.Hosts {
		if pattern == needle {
			return true
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if needle == suffix || strings.HasSuffix(needle, "."+suffix) {
				return true
			}
		}
	}
	return false
}

// normaliseResolver turns a resolver setting into a dialable address, defaulting the DNS port.
func normaliseResolver(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("no address")
	}
	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		if host == "" {
			return "", fmt.Errorf("names a port but no host")
		}
		if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
			return "", fmt.Errorf("port %q is not a port number", port)
		}
		return net.JoinHostPort(host, port), nil
	}
	// No port: an IP literal takes 53. A bare IPv6 literal reaches here too, which SplitHostPort
	// cannot distinguish from a host:port, so it is parsed as an address before being joined.
	if net.ParseIP(trimmed) == nil {
		return "", fmt.Errorf("is not an IP address, and a resolver has to be reachable without a lookup " +
			"of its own")
	}
	return net.JoinHostPort(trimmed, "53"), nil
}

// lookup answers one hostname, through the test seam when there is one and the configured resolver
// otherwise.
//
// It returns STRING addresses rather than net.IPAddr because that is what the family filter and the
// dialer both consume, and a net.IPAddr carries a zone name a filter would have to strip and a dialer
// would have to put back.
func (r ResolutionSettings) lookup(ctx context.Context, host string) ([]string, error) {
	if r.Lookup != nil {
		return r.Lookup(ctx, host)
	}
	resolver := r.resolver()
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return out, nil
}

// resolver returns the *net.Resolver these settings ask for, or nil for the system one.
//
// PreferGo is set because the whole point is to send queries somewhere the platform resolver would
// not: cgo's resolver reads the system configuration and ignores the Dial hook entirely, so leaving it
// to choose would produce a setting that appears to apply and does not.
func (r ResolutionSettings) resolver() *net.Resolver {
	if r.Policy != ResolutionResolver {
		return nil
	}
	addr, err := normaliseResolver(r.Resolver)
	if err != nil {
		// Unreachable through the API, which validates first. A resolver that cannot be addressed
		// falls back to the system one rather than failing every dial, and Validate is the place that
		// says so to the operator.
		return nil
	}
	timeout := time.Duration(r.TimeoutMS) * time.Millisecond
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// dialer builds the net.Dialer every plaintext dial in this package goes through: the connect bound
// and the lookup policy in one place, so a new dial site cannot accidentally get the old literals.
func (n NetworkSettings) dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   time.Duration(n.Timeouts.ConnectMS) * time.Millisecond,
		KeepAlive: 30 * time.Second,
		Resolver:  n.Resolution.resolver(),
	}
}

// exchangeTimeout is the total bound for one exchange, as a duration.
func (n NetworkSettings) exchangeTimeout() time.Duration {
	return time.Duration(n.Timeouts.TotalMS) * time.Millisecond
}

// readTimeout is how long to wait for one response, which is the streaming bound for a host that has
// been declared open-ended and the ordinary read or total bound for everything else.
//
// The fall-through order matters: read_ms is the specific bound and wins when set, total_ms stands in
// when it is not, and zero means "no deadline of our own" so the caller's context decides. Returning
// the total here rather than nothing is what preserves the previous behaviour, where
// SenderConfig.Timeout was the only deadline a raw read ever had.
func (n NetworkSettings) readTimeout(host string) time.Duration {
	if n.Streaming.isStreaming(host) {
		return time.Duration(n.Streaming.TimeoutMS) * time.Millisecond
	}
	if n.Timeouts.ReadMS > 0 {
		return time.Duration(n.Timeouts.ReadMS) * time.Millisecond
	}
	return n.exchangeTimeout()
}
