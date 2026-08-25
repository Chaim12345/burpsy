package sender

import (
	"context"
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
	Overrides []HostOverride `json:"overrides"`
	Policy    ResolutionPolicy `json:"policy"`
	// Resolver is the address queries go to under ResolutionResolver. A bare address takes port 53.
	Resolver string `json:"resolver"`
	// TimeoutMS bounds one lookup. Zero means the resolver's own default.
	TimeoutMS int `json:"timeout_ms"`
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
	return n.Streaming.validate()
}

func (r ResolutionSettings) validate() error {
	switch r.Policy {
	case ResolutionSystem, ResolutionResolver:
	default:
		return fmt.Errorf("resolution.policy is %q, and the only lookup policies are %q and %q",
			r.Policy, ResolutionSystem, ResolutionResolver)
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
func (r ResolutionSettings) resolveHost(host string) (string, bool) {
	needle := strings.ToLower(host)
	for _, o := range r.Overrides {
		if o.Enabled && o.Host == needle {
			return o.Address, true
		}
	}
	return "", false
}

// dialAddress is the address a dial to host:port should actually use, after the override table.
func (n NetworkSettings) dialAddress(host string, port uint16) string {
	if addr, ok := n.Resolution.resolveHost(host); ok {
		return net.JoinHostPort(addr, strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
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
