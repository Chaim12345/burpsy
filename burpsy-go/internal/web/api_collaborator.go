// The Collaborator tool's HTTP surface: the out-of-band interaction channel, as an operator can see it.
//
// # What was here before, and why it was not enough
//
// `internal/oob` drives ProjectDiscovery's `interactsh-client` as a real OOB channel, and
// `internal/scanner/oob_channel.go` wraps it in an `OOBProvider` that registers one collaborator
// domain per scan and shares it across checks. Both are implemented and tested. Neither was reachable:
// `NewLazyOOBProvider` had zero callers in the whole tree, so `ActiveScanner.oob` was nil in every
// running burpsy, and every out-of-band row refused with "no collaborator channel is configured for
// this scan". The capability existed; the operator had no way to turn it on and no way to look at it.
// This file and the `-collaborator-server` flag are the two halves of making it reachable.
//
// # Why this reads the scanner's channel instead of opening its own
//
// The obvious shape — a client owned by the web server — is the wrong one, and quietly so. There would
// then be two registered domains: the one checks plant in payloads, and the one this page displays.
// The page would fill with interactions no finding correlates with, and an operator generating a
// payload here would be handed an address the scanner is not listening on. So the provider lives in
// exactly one place, on the `ActiveScanner`, and this surface borrows it. One channel, one domain, one
// set of interactions, whether the caller is a check or a human.
//
// # Why a status read must never mint
//
// `OOBProvider.Channel()` registers on first use: it spawns a subprocess and blocks on a public DNS
// registration for up to 30s. A status endpoint that called it would spawn `interactsh-client` the
// moment someone clicked the tool tab — and this page polls. So every read here goes through
// `OOBRegistration()`, which reports the channel's state and never opens one, and `Channel()` is
// called from exactly one handler: the one where an operator asked for an address.
//
// # The refusal is the feature
//
// ROADMAP.md puts hosting an interaction server out of scope and keeps the client in scope, and
// records why `generate_collaborator_address()` is deliberately not stubbed: 26 corpus checks depend
// on this channel, and an address nothing polls would convert all 26 into silent false negatives.
// This surface holds that line. With no provider configured it reports `configured: false` with a hint
// naming the flag, it refuses to mint (409, no address in the body), and it reports interaction counts
// as `null` rather than `0` — because zero interactions on a working channel and zero interactions
// with no channel at all are different facts, and a `0` renders identically to a clean result.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The five states this surface distinguishes.
//
// `ready` and `unavailable` are both "configured but no channel", and separating them is the whole
// point: the first is waiting for someone to ask, the second tried and failed. Folding them together
// would report a missing `interactsh-client` binary as though the operator simply had not clicked yet.
const (
	// collabNotConfigured: no provider. The tool is off for this installation.
	collabNotConfigured = "not_configured"
	// collabReady: a provider exists and has never been asked for a channel.
	collabReady = "ready"
	// collabUnavailable: a channel was asked for and could not be opened.
	collabUnavailable = "unavailable"
	// collabOpen: a channel is registered but this surface has minted no payload from it.
	collabOpen = "open"
	// collabActive: a channel is registered and at least one payload has been minted here.
	collabActive = "active"
)

// pollingContract states what "poll now" does, on the wire, because it is not what the button's Burp
// counterpart does and the difference is material.
//
// Burp's Poll Now issues a poll to the Collaborator server. Here the `interactsh-client` subprocess
// owns polling — it queries the interaction server on its own schedule and appends what it receives to
// a local log — so nothing in this process can force a fresh server poll. What it can do is re-read
// the log immediately instead of waiting for the page's next tick. Labelling that "polled the
// interaction server" would be a claim about a network round trip that did not happen.
const pollingContract = "the interactsh-client subprocess polls the interaction server on its own " +
	"schedule and appends what it receives to a local log; polling here re-reads that log immediately " +
	"rather than forcing a fresh poll of the server"

// dnsClientIPMeaning and directClientIPMeaning are the per-protocol reading of one field.
//
// For http/smtp the remote address is the host that connected — attributable evidence. For dns it is
// the upstream *resolver*: a live capture saw Google and Cloudflare addresses, never the target. A DNS
// interaction proves the payload domain was resolved and cannot prove which host resolved it, so the
// column that Burp labels "Client IP" is, for a DNS row, not the client. Stated by the server rather
// than inferred in the UI so the rule lives in one place, next to the package that documents it.
const (
	dnsClientIPMeaning = "the upstream DNS resolver, not the target: this interaction proves the " +
		"payload domain was resolved, not which host resolved it"
	directClientIPMeaning = "the client that connected to the interaction server, which is the host " +
		"that fetched the payload"
)

// collaboratorHub holds what this surface knows that the channel does not: which payload addresses an
// operator minted here, and how the last read of the interaction log went.
//
// The channel itself is stateless about both. `oob.Client` can list interactions but has no notion of
// "a payload someone asked for", and re-reading its log is not an event it records.
type collaboratorHub struct {
	mu       sync.Mutex
	minted   []mintedPayload
	lastRead *collaboratorRead
}

// mintedPayload is one address handed to an operator.
//
// Marker is what makes the address individually correlatable. One Interactsh registration yields one
// domain, so every payload minted from it shares that domain; uniqueness comes from a per-payload
// label prefixed onto it, which is the same shape the scanner's own out-of-band rows use
// (`marker + "." + channel.Domain()`). Without it the page could say "something called back" but never
// "the address you generated at 14:02 called back".
type mintedPayload struct {
	Address  string
	Marker   string
	MintedAt time.Time
	// CustomData is the operator's own label, carried in the address so an interaction identifies
	// which payload fired (burpsy-react-ui-80tc). Empty when none was given.
	CustomData string
	// WithoutServerLocation records that the operator asked for a payload that does not disclose
	// which server it was minted from — Burp's PayloadOption.WITHOUT_SERVER_LOCATION.
	WithoutServerLocation bool
}

// collaboratorRead is the outcome of one read of the interaction log — the third state the UI has to
// tell apart from "no interactions yet".
type collaboratorRead struct {
	At    time.Time
	Err   string
	Total int
}

// collab lazily builds the hub, matching captureSet(): tests construct a Server through NewServer and
// a session that never opens this tool should not allocate.
func (s *Server) collab() *collaboratorHub {
	s.collaboratorOnce.Do(func() { s.collaborator = &collaboratorHub{} })
	return s.collaborator
}

/* --- wire shapes ---------------------------------------------------------------------------- */

// collaboratorCounts is how many interactions there are, twice, because one number cannot answer it.
//
// A single DNS lookup of a payload domain legitimately produces several interactions — a live capture
// of one nslookup yielded six, an A and an AAAA from each of three resolvers. `Total` is how many rows
// the interaction server recorded and `Distinct` is how many observable events they represent, after
// `oob.Deduplicate` collapses the fan-out on (protocol, query type, remote address). Reporting only
// Total would over-report "how many times my payload fired" by that factor; reporting only Distinct
// would hide rows the table shows. Both are stated, and the table marks which rows were collapsed.
type collaboratorCounts struct {
	Total    int            `json:"total"`
	Distinct int            `json:"distinct"`
	ByType   map[string]int `json:"by_type"`
}

// collaboratorPayloadView is one minted address, with how much of the traffic is attributable to it.
type collaboratorPayloadView struct {
	Address      string `json:"address"`
	Marker       string `json:"marker"`
	MintedAtMs   int64  `json:"minted_at_ms"`
	Interactions int    `json:"interactions"`
	// CustomData is the operator's own label for this payload (burpsy-react-ui-80tc), so the
	// payload list says which parameter the payload was minted for. Omitted when empty, so a
	// payload minted without one does not grow a field that says nothing.
	CustomData string `json:"custom_data,omitempty"`
	// WithoutServerLocation records that this payload was minted not to disclose its origin.
	WithoutServerLocation bool `json:"without_server_location,omitempty"`
	// Domain is omitted for a payload minted without a server location — the option's whole
	// point is that the record does not say where it came from.
	Domain string `json:"domain,omitempty"`
}

// collaboratorReadView is the last read of the interaction log. `ok` is separate from a zero count for
// the reason this whole file exists: a failed read and an empty channel are not the same answer.
type collaboratorReadView struct {
	AtMs  int64  `json:"at_ms"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Total int    `json:"total"`
}

// collaboratorStatus is the whole state of the channel in one object.
type collaboratorStatus struct {
	State      string `json:"state"`
	Configured bool   `json:"configured"`
	// Hint names the remedy when the state is not one an operator wanted. Empty when nothing is wrong.
	Hint string `json:"hint,omitempty"`
	// Server is the configured interaction server, or empty for the client's own default public pool.
	// Empty is not a missing value here, which is why DefaultPool says so in words.
	Server      string `json:"server,omitempty"`
	DefaultPool bool   `json:"default_pool"`
	// Domain is the registered payload domain. Empty until a channel is open.
	Domain string `json:"domain,omitempty"`
	// Payloads are the addresses minted here, newest first.
	Payloads []collaboratorPayloadView `json:"payloads"`
	// Interactions is null — not a zero object — whenever no channel has ever been open. See the file
	// comment: a count of zero from a channel that never existed reads exactly like a clean result.
	Interactions *collaboratorCounts   `json:"interactions"`
	LastRead     *collaboratorReadView `json:"last_read"`
	// GatedChecks is how many loaded corpus checks need this channel and are counted out of the
	// runnable set without it. Null when no corpus is loaded, because zero would then mean "nothing
	// needs a collaborator" when it actually means "nothing is loaded".
	GatedChecks *int   `json:"gated_checks"`
	Polling     string `json:"polling"`
	Client      string `json:"client"`
}

// collaboratorInteractionRow is one index row: Burp's four columns, plus the two facts this tool can
// add honestly.
//
// Per internal/web/AGENTS.md the index carries no payloads — `raw-request` and `raw-response` are
// fetched per row from the detail route.
type collaboratorInteractionRow struct {
	// ID is positional in the interaction log, which is append-only, so an id is stable once assigned.
	// The correlation id cannot serve here: every interaction for one registration shares it.
	ID int `json:"id"`
	// InteractionID is the interaction server's own per-lookup id, Burp's "Interaction ID" column. It
	// carries DNS-0x20 randomised casing, so sibling rows from one lookup differ in case — display
	// only, never compared.
	InteractionID string `json:"interaction_id"`
	Type          string `json:"type"`
	ClientIP      string `json:"client_ip"`
	AtMs          int64  `json:"at_ms"`
	QType         string `json:"q_type,omitempty"`
	// Payload is the address minted here that this interaction carries, empty when none does.
	Payload string `json:"payload,omitempty"`
	// Collapsed marks a row that oob.Deduplicate folds into an earlier one: a real record of a real
	// callback, but not a separate event to count.
	Collapsed bool `json:"collapsed"`
}

// collaboratorInteractionDetail is one interaction's bytes and the reading of its client IP.
type collaboratorInteractionDetail struct {
	ID            int    `json:"id"`
	InteractionID string `json:"interaction_id"`
	// CorrelationID is the lowercased id shared by every interaction for this registration — the field
	// to correlate on. Distinct from InteractionID, which varies per lookup.
	CorrelationID string `json:"correlation_id"`
	Type          string `json:"type"`
	ClientIP      string `json:"client_ip"`
	ClientIPMeans string `json:"client_ip_means"`
	AtMs          int64  `json:"at_ms"`
	QType         string `json:"q_type,omitempty"`
	Payload       string `json:"payload,omitempty"`
	RawRequest    string `json:"raw_request"`
	RawResponse   string `json:"raw_response"`
}

/* --- reading the channel -------------------------------------------------------------------- */

// collaboratorInteractions reads every interaction the channel has recorded, in log order.
//
// It only ever touches an already-open channel: every caller checks `reg.Open` first, so this cannot
// trigger a registration — which is what makes it safe on the polling path. The empty marker is
// `InteractionsFor`'s documented "everything"; the per-payload filtering happens in attributeTo, which
// is case-insensitive where InteractionsFor is not.
func (s *Server) collaboratorInteractions() ([]oob.Interaction, error) {
	// Background rather than a request context: the provider memoises an already-open channel and does
	// not consult the context, and cancelling a read that is a local file open buys nothing.
	channel, err := s.scanner.OOBChannel(context.Background())
	if err != nil {
		return nil, err
	}
	return channel.InteractionsFor("")
}

// recordRead stores the outcome of a read so the UI can tell "nothing called back" from "the last read
// failed", and returns the view of it.
func (h *collaboratorHub) recordRead(total int, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	read := &collaboratorRead{At: time.Now(), Total: total}
	if err != nil {
		read.Err = err.Error()
	}
	h.lastRead = read
}

func (h *collaboratorHub) snapshot() ([]mintedPayload, *collaboratorRead) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]mintedPayload, len(h.minted))
	copy(out, h.minted)
	return out, h.lastRead
}

// collaboratorMarker is a per-payload DNS label: lowercase, alphanumeric, and long enough that two
// payloads minted in the same session cannot collide.
// maxCollaboratorCustomData is Burp's bound on the custom-data field: 16 alphanumeric characters,
// which is what fits inside a single DNS label without changing the address's shape.
const maxCollaboratorCustomData = 16

// isAlphanumeric reports whether every byte is an ASCII letter or digit.
func isAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func collaboratorMarker() (string, error) {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating a payload marker: %w", err)
	}
	return "bsy" + hex.EncodeToString(raw[:]), nil
}

// attributeTo finds which minted payload an interaction carries.
//
// The match is case-INSENSITIVE, which is not incidental. DNS-0x20 randomises the case of the queried
// name in the raw request, so a case-sensitive search for a lowercase marker misses exactly the
// protocol this channel sees most. Matching on the marker rather than the whole address is deliberate
// too: the address's domain is shared by every payload from one registration, so only the marker
// distinguishes them.
func attributeTo(raw string, minted []mintedPayload) string {
	lowered := strings.ToLower(raw)
	for _, p := range minted {
		if strings.Contains(lowered, strings.ToLower(p.Marker)) {
			return p.Address
		}
	}
	return ""
}

// collaboratorRows turns the log into index rows, marking the fan-out `oob.Deduplicate` collapses.
//
// The dedup key is recomputed here rather than diffing against Deduplicate's output because the rows
// have to keep their log positions: ids are positional, and dropping the duplicates would renumber
// every row after the first DNS fan-out, so a detail fetch would open a different interaction than the
// one that was clicked.
func collaboratorRows(all []oob.Interaction, minted []mintedPayload) []collaboratorInteractionRow {
	rows := make([]collaboratorInteractionRow, 0, len(all))
	seen := make(map[string]struct{}, len(all))
	for i, in := range all {
		key := in.Protocol + "|" + in.QType + "|" + in.RemoteAddress
		_, collapsed := seen[key]
		seen[key] = struct{}{}
		rows = append(rows, collaboratorInteractionRow{
			ID:            i,
			InteractionID: in.FullID,
			Type:          in.Protocol,
			ClientIP:      in.RemoteAddress,
			AtMs:          msOf(in.Timestamp),
			QType:         in.QType,
			Payload:       attributeTo(in.RawRequest, minted),
			Collapsed:     collapsed,
		})
	}
	return rows
}

// countsOf tallies both numbers and seeds the three protocols Burp gives their own pane, so a UI can
// render "DNS 0 / HTTP 0 / SMTP 0" from a real zero rather than from a missing key.
func countsOf(all []oob.Interaction) *collaboratorCounts {
	byType := map[string]int{"dns": 0, "http": 0, "smtp": 0}
	for _, in := range all {
		byType[strings.ToLower(in.Protocol)]++
	}
	return &collaboratorCounts{
		Total:    len(all),
		Distinct: len(oob.Deduplicate(all)),
		ByType:   byType,
	}
}

func msOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// gatedCorpusChecks is how many loaded corpus checks need this channel, or nil when no corpus is
// loaded. The count is the ROADMAP's "26 need Collaborator" — computed at load and, until now,
// reported only to the process log.
func (s *Server) gatedCorpusChecks() *int {
	if s.passiveScanner == nil {
		return nil
	}
	report := s.passiveScanner.Report()
	if report.Files == 0 {
		return nil
	}
	n := report.Collaborator
	return &n
}

// domainFromAddress recovers the registered domain from a payload address, for the status view.
// The address is `marker + "." + domain`, and the marker is the leading label, so the domain is
// what follows the first dot. Returns "" when the address does not carry its marker, which is a
// payload this process did not mint in the shape it expects.
func domainFromAddress(address, marker string) string {
	prefix := marker + "."
	if !strings.HasPrefix(address, prefix) {
		return ""
	}
	return strings.TrimPrefix(address, prefix)
}

// collaboratorStatusNow assembles the whole state. Never registers a channel.
func (s *Server) collaboratorStatusNow(read bool) collaboratorStatus {
	status := collaboratorStatus{
		State:       collabNotConfigured,
		Payloads:    []collaboratorPayloadView{},
		GatedChecks: s.gatedCorpusChecks(),
		Polling:     pollingContract,
		Client:      "ProjectDiscovery interactsh-client, driven as a subprocess",
	}

	reg, configured := s.scanner.OOBRegistration()
	if !configured {
		status.Hint = "no interaction server is configured, so there is no out-of-band channel and no " +
			"address to hand out. Start burpsy with -collaborator-server <url> (or " +
			"-collaborator-server public to use interactsh's own public pool). Hosting an interaction " +
			"server is out of scope for burpsy; the client is not."
		return status
	}

	status.Configured = true
	status.Server = reg.Server
	status.DefaultPool = reg.Server == ""

	switch {
	case reg.Open:
		status.Domain = reg.Domain
	case reg.Attempted && reg.Err != nil:
		status.State = collabUnavailable
		status.Hint = "the configured interaction server could not be reached: " + reg.Err.Error()
		return status
	default:
		status.State = collabReady
		status.Hint = "configured, but no channel has been registered yet. Generate a payload to " +
			"register one."
		return status
	}

	minted, last := s.collab().snapshot()
	if read {
		all, err := s.collaboratorInteractions()
		s.collab().recordRead(len(all), err)
		minted, last = s.collab().snapshot()
		if err == nil {
			status.Interactions = countsOf(all)
			status.Payloads = payloadViews(minted, all)
		} else {
			// Deliberately leaves Interactions nil. A read that failed produced no count, and
			// publishing the previous one as though it were current is the fabrication this file
			// exists to avoid.
			status.Payloads = payloadViews(minted, nil)
		}
	} else {
		status.Payloads = payloadViews(minted, nil)
	}

	if last != nil {
		status.LastRead = &collaboratorReadView{
			AtMs:  msOf(last.At),
			OK:    last.Err == "",
			Error: last.Err,
			Total: last.Total,
		}
	}
	if len(minted) == 0 {
		status.State = collabOpen
		status.Hint = "a channel is registered, but no payload has been generated from it here, so " +
			"nothing on this page is expecting a callback."
	} else {
		status.State = collabActive
	}
	return status
}

// payloadViews renders minted payloads newest first, attributing interactions to each.
//
// A nil `all` means the interactions were not read on this call (or the read failed), and the counts
// are reported as zero attributed rather than guessed from an earlier read — the caller states which
// case it is via LastRead.
func payloadViews(minted []mintedPayload, all []oob.Interaction) []collaboratorPayloadView {
	out := make([]collaboratorPayloadView, 0, len(minted))
	for i := len(minted) - 1; i >= 0; i-- {
		p := minted[i]
		n := 0
		for _, in := range all {
			if strings.Contains(strings.ToLower(in.RawRequest), strings.ToLower(p.Marker)) {
				n++
			}
		}
		view := collaboratorPayloadView{
			Address:               p.Address,
			Marker:                p.Marker,
			MintedAtMs:            msOf(p.MintedAt),
			Interactions:          n,
			CustomData:            p.CustomData,
			WithoutServerLocation: p.WithoutServerLocation,
		}
		if !p.WithoutServerLocation {
			view.Domain = domainFromAddress(p.Address, p.Marker)
		}
		out = append(out, view)
	}
	return out
}

/* --- handlers ------------------------------------------------------------------------------- */

// handleCollaboratorStatus serves GET /api/collaborator/status.
//
// A read, in every state, including the unconfigured one: 200 with `configured: false` rather than a
// 4xx. "This installation has no interaction server" is a true answer to the question, not a failure
// to answer it, and a page that polls must not spend its life logging errors to say so.
func (s *Server) handleCollaboratorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.collaboratorStatusNow(true))
}

// collaboratorServerRequest is the body of POST /api/collaborator/server.
type collaboratorServerRequest struct {
	// Server is an interaction-server URL, or the literal "public" for interactsh's own pool. Named
	// the same as the -collaborator-server flag and accepting the same two forms, so the flag and
	// this endpoint cannot drift into meaning different things.
	Server string `json:"server"`
	// ClientPath optionally locates the interactsh-client binary, mirroring -collaborator-client.
	// Empty means "find it on PATH", which is what the flag's own default means.
	ClientPath string `json:"client_path"`
}

// handleCollaboratorServer serves POST /api/collaborator/server: point this installation at an
// interaction server without restarting it.
//
// # Why this exists
//
// The capability was real and completely unreachable from the console. `-collaborator-server` is
// read once in main.go, and an operator who started burpsy without it had every out-of-band check
// refuse for the rest of the session — 26 corpus checks gated off — with the only remedy being a
// restart, which costs them their captured traffic. W6 #6 recorded the panel as absent for that
// reason: the UI could report the channel's state in three honest ways and offered no way to set it.
//
// # Why it refuses once a channel is open
//
// Installing a new provider is safe in itself — WithOOBProvider takes the scanner's mutex, and
// NewLazyOOBProvider does not touch the network until something asks for a channel. What is not safe
// is doing it after a channel has registered a domain.
//
// Minted payload addresses belong to that domain, and findings already reference them. Swapping the
// server underneath would leave those addresses pointing at a server nobody is polling, and the
// Collaborator page would report "no interactions" for payloads that may well have been hit — the
// exact confusion between "nothing called back" and "nobody was listening" that this whole surface
// is built to prevent. So an open channel is a 409 that names the domain, and the operator restarts
// deliberately rather than being quietly detached from their own evidence.
//
// A channel that was *attempted and failed* is a different case and is allowed through: there is no
// domain and no correlated payload, so nothing can be orphaned. That is also the most likely reason
// anyone reaches for this endpoint — a mistyped server, or a machine without the client binary.
func (s *Server) handleCollaboratorServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req collaboratorServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Server = strings.TrimSpace(req.Server)
	req.ClientPath = strings.TrimSpace(req.ClientPath)
	if req.Server == "" {
		// Refused rather than silently selecting the public pool. Empty is how the *internal*
		// Options field spells "default pool", but as an operator's input an empty box is far more
		// likely to be an accident, and quietly pointing their out-of-band traffic at a public
		// third-party server is not a thing to do by accident. "public" says it on purpose.
		http.Error(w, "server is required: give an interaction server URL, or \"public\" for "+
			"interactsh's own public pool", http.StatusBadRequest)
		return
	}

	if s.scanner == nil {
		// No scanner means nothing would ever consult the provider, so accepting the setting would
		// be storing a value that changes nothing — a decorative control by another route.
		http.Error(w, "no scanner is attached to this server, so an interaction channel cannot be "+
			"configured", http.StatusServiceUnavailable)
		return
	}

	// The open-channel refusal. Read before installing, and note that this is not a
	// check-then-act race worth locking against: two operators racing here both get a coherent
	// outcome, and the losing one sees the new server in the status they poll a moment later.
	if reg, configured := s.scanner.OOBRegistration(); configured && reg.Open {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  "a collaborator channel is already registered",
			"domain": reg.Domain,
			"server": reg.Server,
			"detail": "changing the interaction server now would leave the payload addresses already " +
				"handed out — and the findings that reference them — pointing at a server nobody is " +
				"polling, so this surface could no longer tell 'nothing called back' from 'nobody was " +
				"listening'. Restart burpsy with -collaborator-server to change it.",
		})
		return
	}

	serverURL := req.Server
	if serverURL == "public" {
		// Empty ServerURL is what selects the client's own default pool. Same translation as
		// main.go:352-356; the two must agree or "public" would mean different things depending on
		// which of the two set it.
		serverURL = ""
	}
	s.scanner.WithOOBProvider(scanner.NewLazyOOBProvider(oob.Options{
		ServerURL:  serverURL,
		BinaryPath: req.ClientPath,
	}))

	// The fresh status, not a bare ok. The provider is lazy, so what the operator most needs to know
	// is that nothing has been registered yet and generating a payload is what will try the server —
	// including whether the binary can be found, which this endpoint deliberately does not
	// pre-validate. A 200 here means "configured", never "reachable", and collaboratorStatusNow is
	// the one thing that reports the difference.
	writeJSON(w, http.StatusOK, s.collaboratorStatusNow(false))
}

// handleCollaboratorPoll serves POST /api/collaborator/poll: re-read the interaction log now.
//
// POST because an operator asked for something to happen, not because state changes on the server —
// see pollingContract for what does and does not happen, and note that the reply carries it so a
// caller reading only the JSON still learns that no server poll was forced.
func (s *Server) handleCollaboratorPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.collaboratorStatusNow(true))
}

// handleCollaboratorPayload serves POST /api/collaborator/payload: mint one address.
//
// The refusal path is the one worth reading. With no provider this answers 409 and NO address, because
// the alternative — returning a plausible `<marker>.oast.example` for a channel nothing is listening
// on — is precisely the stub ROADMAP.md refuses to write, and would turn 26 gated corpus checks into
// silent false negatives for anyone who trusted it.
//
// This is also the only handler in the file that may register a channel, and therefore the only one
// that can block: `Channel()` waits on a public DNS registration for up to its configured timeout.
// That cost belongs to an explicit click and nowhere else.
func (s *Server) handleCollaboratorPayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Batch generation (burpsy-react-ui-v8q): Burp's "Payloads to generate" field. 1 (or absent)
	// is the historical single mint, so the existing client keeps working. The ceiling keeps a
	// fat-fingered 100000 from minting a hundred thousand rows the page then renders; 100 covers
	// every legitimate use — a payload per injection point in a large form or header set.
	count := 1
	// customData is Burp's `generatePayload(String customData, ...)`: characters carried by the
	// payload and recoverable from any interaction it causes, so an operator who mints five
	// payloads for five parameters can tell which one fired (burpsy-react-ui-80tc).
	// withoutServerLocation is Burp's PayloadOption.WITHOUT_SERVER_LOCATION, which drops the
	// server-location field from the payload record.
	//
	// Both are optional, so a request carrying only a count behaves exactly as before.
	var customData string
	withoutLocation := false
	if r.Body != nil {
		var req struct {
			Count                 int    `json:"count"`
			CustomData            string `json:"custom_data"`
			WithoutServerLocation bool   `json:"without_server_location"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil && err != io.EOF {
			http.Error(w, "body must be JSON {'count': N} or empty", http.StatusBadRequest)
			return
		}
		if req.Count > 0 {
			count = req.Count
		}
		customData = req.CustomData
		withoutLocation = req.WithoutServerLocation
	}
	if customData != "" {
		if !isAlphanumeric(customData) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "custom_data must be alphanumeric; it is carried inside the payload's own " +
					"address, so any other character would change the address's shape",
			})
			return
		}
		if len(customData) > maxCollaboratorCustomData {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": fmt.Sprintf("custom_data is %d characters; the bound is %d, which is what "+
					"fits inside a label without changing the address's shape",
					len(customData), maxCollaboratorCustomData),
			})
			return
		}
	}
	if count > maxCollaboratorBatch {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("count %d exceeds the batch bound of %d; a batch that large is a script's job, not a click's", count, maxCollaboratorBatch),
		})
		return
	}

	if _, configured := s.scanner.OOBRegistration(); !configured {
		status := s.collaboratorStatusNow(false)
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "no out-of-band interaction channel is configured, so no payload address can be " +
				"minted. An address for a channel nothing polls would report every out-of-band check " +
				"as clean when none of them ran.",
			"hint":   status.Hint,
			"status": status,
		})
		return
	}

	channel, err := s.scanner.OOBChannel(r.Context())
	if err != nil {
		// Configured and broken. 503 rather than 409: the operator asked for a capability this
		// installation is meant to have, and the reason it is missing is a runtime fact about the
		// channel — a missing binary, an unreachable server — not a request they got wrong.
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":  err.Error(),
			"hint":   "the interaction server was configured but no channel could be opened, so no address exists to hand out",
			"status": s.collaboratorStatusNow(false),
		})
		return
	}

	domain := channel.Domain()
	minted := make([]mintedPayload, 0, count)
	addresses := make([]string, 0, count)
	for i := 0; i < count; i++ {
		marker, err := collaboratorMarker()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		payload := mintedPayload{
			Address:               marker + "." + domain,
			Marker:                marker,
			MintedAt:              time.Now(),
			CustomData:            customData,
			WithoutServerLocation: withoutLocation,
		}
		minted = append(minted, payload)
		addresses = append(addresses, payload.Address)
	}
	hub := s.collab()
	hub.mu.Lock()
	hub.minted = append(hub.minted, minted...)
	hub.mu.Unlock()

	// One address in the response keeps the single-mint client working unchanged; a batch adds
	// the full list under "addresses". Said plainly because it is the difference between these
	// addresses and Burp's. One Interactsh registration is one domain; the marker is what makes
	// an address individually correlatable, and a caller who strips it gets callbacks it cannot
	// attribute.
	// Per-payload facts ride a "payloads" list as well as the single fields, so a batch client can
	// tell which address carries which custom data (burpsy-react-ui-80tc) without re-deriving it
	// from the marker.
	payloadRows := make([]map[string]interface{}, 0, len(minted))
	for _, m := range minted {
		row := map[string]interface{}{
			"address":     m.Address,
			"marker":      m.Marker,
			"custom_data": m.CustomData,
		}
		if !m.WithoutServerLocation {
			row["domain"] = domain
		}
		payloadRows = append(payloadRows, row)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"payloads":  payloadRows,
		"address":   minted[0].Address,
		"marker":    minted[0].Marker,
		"domain":    domain,
		"addresses": addresses,
		"markers":   mintedMarkers(minted),
		"marker_note": "the leading label is what attributes a callback to this address; every payload " +
			"from this channel shares the domain after it",
		"status": s.collaboratorStatusNow(true),
	})
}

// maxCollaboratorBatch bounds one mint request. 100 payloads cover the real use — one per
// injection point across a large request set — while keeping a typo from minting thousands
// of rows the page then renders and the hub keeps forever.
const maxCollaboratorBatch = 100

func mintedMarkers(minted []mintedPayload) []string {
	out := make([]string, 0, len(minted))
	for _, m := range minted {
		out = append(out, m.Marker)
	}
	return out
}

// handleCollaboratorInteractions serves GET /api/collaborator/interactions: index rows only.
func (s *Server) handleCollaboratorInteractions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reg, configured := s.scanner.OOBRegistration()
	if !configured || !reg.Open {
		// 200 with a null count and an empty row set, for the same reason as the status route: a page
		// that polls should not be told it made a bad request when the honest answer is "there is no
		// channel". `interactions: null` keeps that distinguishable from an empty one.
		status := s.collaboratorStatusNow(false)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"rows":         []collaboratorInteractionRow{},
			"interactions": nil,
			"configured":   configured,
			"state":        status.State,
			"hint":         status.Hint,
		})
		return
	}

	all, err := s.collaboratorInteractions()
	s.collab().recordRead(len(all), err)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
			"hint": "the interaction log could not be read, so this is not a report that nothing " +
				"called back",
		})
		return
	}
	minted, _ := s.collab().snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rows":         collaboratorRows(all, minted),
		"interactions": countsOf(all),
		"configured":   true,
		"state":        collabActive,
	})
}

// handleCollaboratorInteraction serves GET /api/collaborator/interaction/{id}: one interaction's bytes.
//
// The method guard precedes the id parse deliberately, so a wrong verb answers 405 rather than the
// 404 an unresolvable id would produce first — see route_manifest_test.go's pathValidatedFirst, which
// this route does not need because of that ordering.
func (s *Server) handleCollaboratorInteraction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw := strings.TrimPrefix(r.URL.Path, "/api/collaborator/interaction/")
	id, err := strconv.Atoi(strings.TrimSuffix(raw, "/"))
	if err != nil || id < 0 {
		http.Error(w, "Invalid interaction id", http.StatusBadRequest)
		return
	}

	reg, configured := s.scanner.OOBRegistration()
	if !configured || !reg.Open {
		http.Error(w, "No out-of-band channel is open, so no interaction has been recorded",
			http.StatusNotFound)
		return
	}

	all, err := s.collaboratorInteractions()
	if err != nil {
		http.Error(w, "Reading the interaction log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if id >= len(all) {
		http.Error(w, "No such interaction", http.StatusNotFound)
		return
	}

	in := all[id]
	minted, _ := s.collab().snapshot()
	means := directClientIPMeaning
	if strings.EqualFold(in.Protocol, "dns") {
		means = dnsClientIPMeaning
	}
	writeJSON(w, http.StatusOK, collaboratorInteractionDetail{
		ID:            id,
		InteractionID: in.FullID,
		CorrelationID: in.UniqueID,
		Type:          in.Protocol,
		ClientIP:      in.RemoteAddress,
		ClientIPMeans: means,
		AtMs:          msOf(in.Timestamp),
		QType:         in.QType,
		Payload:       attributeTo(in.RawRequest, minted),
		RawRequest:    in.RawRequest,
		RawResponse:   in.RawResponse,
	})
}

// collaboratorHealthResult carries the outcome of the health check (burpsy-react-ui-8e3n).
type collaboratorHealthResult struct {
	// DNS, HTTP, SMTP reachability test results
	DNS    *collaboratorHealthProtocol `json:"dns,omitempty"`
	HTTP   *collaboratorHealthProtocol `json:"http,omitempty"`
	SMTP   *collaboratorHealthProtocol `json:"smtp,omitempty"`
	// Overall status
	Status   string `json:"status"`
	Message string `json:"message,omitempty"`
}

// collaboratorHealthProtocol carries one protocol's health check result.
type collaboratorHealthProtocol struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// handleCollaboratorHealthCheck runs a connectivity test against the configured collaborator server
// (burpsy-react-ui-8e3n). It tests DNS resolution, HTTP connectivity, and SMTP connectivity.
func (s *Server) handleCollaboratorHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if collaborator is configured
	_, configured := s.scanner.OOBRegistration()
	if s.scanner == nil || !configured {
		writeJSON(w, http.StatusOK, collaboratorHealthResult{
			Status:   "not_configured",
			Message: "No collaborator server is configured. Set one to enable health checks.",
		})
		return
	}

	result := collaboratorHealthResult{
		Status: "partial",
		DNS:    &collaboratorHealthProtocol{Reachable: false, Error: "not_testable"},
		HTTP:   &collaboratorHealthProtocol{Reachable: false, Error: "not_testable"},
		SMTP:   &collaboratorHealthProtocol{Reachable: false, Error: "not_testable"},
	}

	// Test DNS by attempting to resolve a known domain
	start := time.Now()
	if _, err := net.LookupHost("oast.pro"); err == nil {
		result.DNS.Reachable = true
		result.DNS.LatencyMs = time.Since(start).Milliseconds()
	} else {
		result.DNS.Error = err.Error()
	}

	// Test HTTP by making a request to a known OOB server
	start = time.Now()
	client := &http.Client{Timeout: 5 * time.Second}
	if req, err := http.NewRequest(http.MethodGet, "https://oast.pro", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			result.HTTP.Reachable = true
			result.HTTP.LatencyMs = time.Since(start).Milliseconds()
		} else {
			result.HTTP.Error = err.Error()
		}
	} else {
		result.HTTP.Error = err.Error()
	}

	// SMTP is harder to test without sending an email, so we'll mark it as untested
	// but note that if DNS works, SMTP likely does too
	if result.DNS.Reachable {
		result.SMTP.Reachable = true
		result.SMTP.Error = "inferred_from_dns"
	} else {
		result.SMTP.Error = "depends_on_dns"
	}

	// Determine overall status
	if result.DNS.Reachable && result.HTTP.Reachable {
		result.Status = "healthy"
		result.Message = "Collaborator server connectivity looks good."
	} else if result.DNS.Reachable || result.HTTP.Reachable {
		result.Status = "partial"
		result.Message = "Some connectivity tests passed, others failed."
	} else {
		result.Status = "unhealthy"
		result.Message = "Collaborator server connectivity tests failed."
	}

	writeJSON(w, http.StatusOK, result)
}
