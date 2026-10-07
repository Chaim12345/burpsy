package vulnapp

// stored (second-order) rows.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by familyRegistrars.
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, reflecting or echoing the same
//     input WITHOUT the defect. That twin is what catches a detector firing on reflection alone.
//     Where no such thing can exist, say why in SafeTwinNotApplicable rather than omitting it.
//   - Handlers must be the real mechanism, not a payload matcher. An endpoint that pattern-matches
//     the payloads it expects grades the check against the fixture author's guesses and passes
//     whether or not the detector works.
//
// # Every submit handler stores a bounded HISTORY, never just the latest value
//
// PlantStoredCanaries walks every insertion point the captured request has (query, body, cookie,
// header) and plants a canary in each - not only the one this handler reads. The seeded request
// here always carries an Origin header (runtime_coverage_test.go's seed sets it on every capture),
// so a submit endpoint gets TWO probes: one with the canary in the query parameter this handler
// reads, one with the canary in the Origin header (which this handler ignores) and the query
// parameter back at its placeholder value. A handler that OVERWRITES a single stored value is not
// safe against that second probe landing after the first - whichever send happens last wins, and it
// can just as easily be the header probe, silently erasing the real canary before anything ever
// renders it. Keeping a short history instead of one slot means the erasing probe adds a harmless
// extra entry rather than deleting the one that matters; every render then shows every value it has
// ever kept, so the canary is not lost to the mechanism's own request(s) it did not need.
//
// # Why six of these ten rows are SafeTwinNotApplicable, and four are not
//
// checks_stored.go's ten evaluators reduce to one question: does a planted canary reappear in a
// specific place (anywhere in the body; inside a <script>/<style> element; inside an
// href/action/src attribute)? Two properties of that mechanism matter here:
//
//  1. Escape-blindness. The canary alphabet is "a-z0-9" (infra_stored.go's storedCanaryAlphabet),
//     so it never contains a character HTML-escaping, URL-escaping or attribute-quoting would
//     change. A page that escapes the value correctly and one that does not produce byte-identical
//     output for this canary. This accounts for the four contextAnywhere rows (Input returned,
//     Password returned, Suspicious transformation, SQL injection second-order - matching the
//     precedent vulnapp.go already sets at /comment), and it also applies to script/style: an
//     alphanumeric canary sits inside a <script>/<style> element whether the app escaped it or
//     not, so no rendering choice keeps it out of that position while still using it there.
//  2. Position admission, for href/action/src. Unlike script/style, an href/action/src target has
//     a real, checkable shape a legitimate value follows: a same-origin path. A safe implementation
//     validates that shape and refuses anything else, so the canary - which is pure alphanumeric
//     and therefore never starts with "/" - is never admitted into the attribute at all; it is
//     replaced with a default and shown separately as escaped text. contextInAttribute only matches
//     inside the attribute's value, so this is a genuine discriminator, not an artefact.
//
// (2) only became buildable after a ledger-bleed defect in checks_stored.go's deferStoredClaim was
// fixed: its resolver used to scan the WHOLE ledger's SecondOrderObservations() with no scoping to
// the claiming exchange, so once ANY endpoint satisfied a position row once, every later stored
// audit - including a genuinely safe one - inherited that stale, unrelated match. Confirmed fixed
// with a standalone repro re-run after the fix (safe twin stays quiet even though the vulnerable
// twin already satisfied the row) before shipping the four twins below.
//
// Corresponding scanner descriptors: StoredCheckDescriptors.

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// storedHistoryLimit bounds every history slice below, so a scan cannot grow one without limit.
const storedHistoryLimit = 20

// storedAppend appends v to *log under mu, capped at storedHistoryLimit, and returns a snapshot
// safe to read without holding the lock.
func storedAppend(mu *sync.Mutex, log *[]string, v string) {
	if v == "" {
		return
	}
	mu.Lock()
	*log = append(*log, v)
	if len(*log) > storedHistoryLimit {
		*log = (*log)[len(*log)-storedHistoryLimit:]
	}
	mu.Unlock()
}

func storedSnapshot(mu *sync.Mutex, log *[]string) []string {
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), *log...)
}

// storedSameOriginPath reports whether v is safe to place in a resource attribute (href, action,
// src): a site-relative path, never an absolute URL, a protocol-relative "//" address, or a
// backslash a browser would later normalise to one. Mirrors vulnapp.go's safeRedirect, which
// documents why the narrower HasPrefix(v, "/") && !HasPrefix(v, "//") alone was itself found
// vulnerable: "/\evil.example/" starts with a single "/" but a browser treats "\" as "/", so the
// effective target is off-site.
func storedSameOriginPath(v string) bool {
	return v != "" &&
		strings.HasPrefix(v, "/") &&
		!strings.HasPrefix(v, "//") &&
		!strings.ContainsAny(v, `\`) &&
		!strings.Contains(v, "://")
}

// storedSafeTarget returns the first same-origin value in history, or "/" if none qualifies - the
// safe renderers' shared fallback logic.
func storedSafeTarget(history []string, fallback string) string {
	for _, v := range history {
		if storedSameOriginPath(v) {
			return v
		}
	}
	return fallback
}

// storedFamilyEndpoints returns this family's manifest entries.
func storedFamilyEndpoints() []Endpoint {
	const noSafeTwinAnywhere = "checks_stored.go's contextAnywhere fires on ANY later reappearance " +
		"of the (alphanumeric-only) canary, escaped or not, so this row is true whether the output " +
		"was escaped or not - a safe twin would report the identical finding, exactly like vulnapp.go's " +
		"/comment entry for \"Input returned in response (stored)\""
	const noSafeTwinElement = "checks_stored.go's contextInsideTag matches the canary's mere presence " +
		"between the opening and closing tag; the alphanumeric-only canary has no character escaping " +
		"would change, so a page that escapes correctly and one that does not put byte-identical " +
		"output inside the element - there is no rendering choice that keeps the value usable there " +
		"while also keeping it out of the matcher's view"

	return []Endpoint{
		// --- contextAnywhere: the canary merely has to reappear anywhere in a later response ---

		{Path: "/st/feedback?message=seed", Row: "Input returned in response (stored)", Stored: true,
			SafeTwinNotApplicable: noSafeTwinAnywhere,
			Note:                  "a message submitted here is rendered verbatim by /st/feedback/list on a later request"},
		{Path: "/st/feedback/list", Note: "renders every stored feedback message; re-fetched by the deferred phase"},

		{Path: "/st/account/password?password=seed", Row: "Password returned in later response", Stored: true,
			SafeTwinNotApplicable: noSafeTwinAnywhere,
			Note:                  "a password submitted here is echoed into the account's activity log by /st/account/activity on a later request"},
		{Path: "/st/account/activity", Note: "renders the account's recent activity, including raw password values; re-fetched by the deferred phase"},

		{Path: "/st/profile/nickname?nickname=seed", Row: "Suspicious input transformation (stored)", Stored: true,
			SafeTwinNotApplicable: noSafeTwinAnywhere,
			Note: "a nickname submitted here comes back upper-cased by /st/profile/card on a later request - recognisable " +
				"but altered, which is what marks the reappearance suspicious rather than a plain echo"},
		{Path: "/st/profile/card", Note: "renders the profile card with the stored, upper-cased nickname history; re-fetched by the deferred phase"},

		{Path: "/st/support/ticket?subject=seed", Row: "SQL injection (second order)", Stored: true,
			SafeTwinNotApplicable: noSafeTwinAnywhere,
			Note: "a ticket subject submitted here is listed unparameterised by /st/support/tickets on a later request, " +
				"standing in for a value a later query reuses without binding it"},
		{Path: "/st/support/tickets", Note: "lists every open ticket subject; re-fetched by the deferred phase"},

		// --- contextInsideTag: the canary has to land inside a specific element's own markup ---

		{Path: "/st/note?text=seed", Row: "Cross-site scripting (stored)", Stored: true,
			SafeTwinNotApplicable: noSafeTwinElement,
			Note:                  "a note submitted here is inlined unescaped into a <script> literal by /st/notes on a later request"},
		{Path: "/st/notes", Note: "renders every stored sticky note inside an inline <script>; re-fetched by the deferred phase"},

		{Path: "/st/theme?accent=seed", Row: "CSS injection (stored)", Stored: true,
			SafeTwinNotApplicable: noSafeTwinElement,
			Note:                  "an accent colour submitted here is inlined unescaped into a <style> rule by /st/theme/page on a later request"},
		{Path: "/st/theme/page", Note: "renders every stored accent colour inside an inline <style> block; re-fetched by the deferred phase"},

		// --- contextInAttribute: the canary has to land inside one attribute's value. These four
		// rows DO have real safe twins: a same-origin check keeps the (never-"/"-shaped) canary out
		// of the attribute entirely, which contextInAttribute can genuinely tell apart. ---
		//
		// Open redirection (stored) and Link manipulation (stored) are bound to the identical
		// contextInAttribute("href") matcher in checks_stored.go, so one sighting satisfies both -
		// the check itself cannot tell them apart, and building two separately-named endpoints for
		// it would misrepresent that as two distinct mechanisms. Their safe twin is likewise shared.
		{Path: "/st/bookmark?destination=seed", Row: "Open redirection (stored)", Stored: true,
			Note: "a destination submitted here is inlined into an <a href> by /st/bookmarks on a later request; " +
				"shares its detection with \"Link manipulation (stored)\" below - checks_stored.go binds both to the same href matcher"},
		{Path: "/st/bookmark?destination=seed", Row: "Link manipulation (stored)", Stored: true,
			Note: "the same submission and rendering as \"Open redirection (stored)\" above; checks_stored.go's " +
				"contextInAttribute(\"href\") cannot distinguish the two rows from one sighting"},
		{Path: "/st/bookmarks", Note: "renders every stored bookmark as a link; re-fetched by the deferred phase"},

		{Path: "/st/bookmark/safe?destination=seed", Row: "Open redirection (stored)", Safe: true, Stored: true,
			Note: "a destination submitted here reaches href only if it is a validated same-origin path " +
				"(mirrors safeRedirect/safeProfileLink); the canary is alphanumeric-only and never starts with \"/\", " +
				"so it is refused and shown only as escaped text by /st/bookmarks/safe"},
		{Path: "/st/bookmark/safe?destination=seed", Row: "Link manipulation (stored)", Safe: true, Stored: true,
			Note: "the same safe submission and rendering as \"Open redirection (stored)\" above"},
		{Path: "/st/bookmarks/safe", Note: "renders the safely-validated bookmark history; re-fetched by the deferred phase"},

		{Path: "/st/form?endpoint=seed", Row: "Form action hijacking (stored)", Stored: true,
			Note: "a workflow endpoint submitted here is inlined into a <form action> by /st/forms on a later request"},
		{Path: "/st/forms", Note: "renders every stored workflow form with its stored action target; re-fetched by the deferred phase"},

		{Path: "/st/form/safe?endpoint=seed", Row: "Form action hijacking (stored)", Safe: true, Stored: true,
			Note: "a workflow endpoint submitted here reaches the form's action only if it is a validated " +
				"same-origin path; the canary never starts with \"/\", so it is refused and shown only as " +
				"escaped text by /st/forms/safe, and the form keeps a fixed, same-origin action"},
		{Path: "/st/forms/safe", Note: "renders the safely-validated workflow form history; re-fetched by the deferred phase"},

		{Path: "/st/widget?ref=seed", Row: "Client-side HTTP parameter pollution (stored)", Stored: true,
			Note: "a reference id submitted here is concatenated unescaped into a <script src> query string by /st/widgets " +
				"on a later request, so a value carrying & or = could add its own parameter to the loaded resource"},
		{Path: "/st/widgets", Note: "renders every stored widget reference inside a <script src> URL; re-fetched by the deferred phase"},

		{Path: "/st/widget/safe?ref=seed", Row: "Client-side HTTP parameter pollution (stored)", Safe: true, Stored: true,
			Note: "a reference id submitted here becomes the script's src only if it is a validated same-origin " +
				"path, never a query string built from the raw value; the canary never starts with \"/\", so it is " +
				"refused and shown only as escaped text by /st/widgets/safe"},
		{Path: "/st/widgets/safe", Note: "renders the safely-validated widget reference history; re-fetched by the deferred phase"},
	}
}

// registerStoredFamily serves this family's routes.
func registerStoredFamily(mux *http.ServeMux) {
	mux.HandleFunc("/st/feedback", storedSubmitFeedback)
	mux.HandleFunc("/st/feedback/list", storedRenderFeedback)

	mux.HandleFunc("/st/account/password", storedSubmitPassword)
	mux.HandleFunc("/st/account/activity", storedRenderActivity)

	mux.HandleFunc("/st/profile/nickname", storedSubmitNickname)
	mux.HandleFunc("/st/profile/card", storedRenderProfileCard)

	mux.HandleFunc("/st/support/ticket", storedSubmitTicket)
	mux.HandleFunc("/st/support/tickets", storedRenderTickets)

	mux.HandleFunc("/st/note", storedSubmitNote)
	mux.HandleFunc("/st/notes", storedRenderNotes)

	mux.HandleFunc("/st/theme", storedSubmitTheme)
	mux.HandleFunc("/st/theme/page", storedRenderTheme)

	mux.HandleFunc("/st/bookmark", storedSubmitBookmark)
	mux.HandleFunc("/st/bookmarks", storedRenderBookmarks)
	mux.HandleFunc("/st/bookmark/safe", storedSubmitSafeBookmark)
	mux.HandleFunc("/st/bookmarks/safe", storedRenderSafeBookmarks)

	mux.HandleFunc("/st/form", storedSubmitForm)
	mux.HandleFunc("/st/forms", storedRenderForms)
	mux.HandleFunc("/st/form/safe", storedSubmitSafeForm)
	mux.HandleFunc("/st/forms/safe", storedRenderSafeForms)

	mux.HandleFunc("/st/widget", storedSubmitWidget)
	mux.HandleFunc("/st/widgets", storedRenderWidgets)
	mux.HandleFunc("/st/widget/safe", storedSubmitSafeWidget)
	mux.HandleFunc("/st/widgets/safe", storedRenderSafeWidgets)
}

// ---------------------------------------------------------------------------
// Feedback: "Input returned in response (stored)"
// ---------------------------------------------------------------------------

var (
	storedFeedbackMu  sync.Mutex
	storedFeedbackLog []string
)

// storedSubmitFeedback persists whatever it is given. Storing untrusted input is not itself the
// defect - the rendering below is.
func storedSubmitFeedback(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedFeedbackMu, &storedFeedbackLog, r.URL.Query().Get("message"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "feedback received\n")
}

// storedRenderFeedback renders every stored message without escaping, which is the defect.
func storedRenderFeedback(w http.ResponseWriter, r *http.Request) {
	entries := storedSnapshot(&storedFeedbackMu, &storedFeedbackLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Feedback received</h1>")
	for _, e := range entries {
		fmt.Fprintf(w, "<p class=\"feedback-item\">%s</p>", e)
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Account activity: "Password returned in later response"
// ---------------------------------------------------------------------------

var (
	storedAccountMu sync.Mutex
	storedPwdLog    []string
)

func storedSubmitPassword(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedAccountMu, &storedPwdLog, r.URL.Query().Get("password"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "password updated\n")
}

// storedRenderActivity writes every raw password value straight into the account's own activity
// log - a real anti-pattern where a "what changed recently" page redisplays a secret rather than
// masking it.
func storedRenderActivity(w http.ResponseWriter, r *http.Request) {
	entries := storedSnapshot(&storedAccountMu, &storedPwdLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Account activity</h1><ul>")
	for _, pwd := range entries {
		fmt.Fprintf(w, "<li>password changed to \"%s\"</li>", pwd)
	}
	fmt.Fprint(w, "</ul></body></html>")
}

// ---------------------------------------------------------------------------
// Profile card: "Suspicious input transformation (stored)"
// ---------------------------------------------------------------------------

var (
	storedProfileMu   sync.Mutex
	storedNicknameLog []string
)

func storedSubmitNickname(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedProfileMu, &storedNicknameLog, r.URL.Query().Get("nickname"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "nickname saved\n")
}

// storedRenderProfileCard renders every stored nickname upper-cased, as a display-name formatter
// would. The ledger's canary comparison is case-insensitive (infra_stored.go's Observe lower-cases
// both sides), so this genuinely alters the value while staying detectable - the "suspicious" part
// of the row is exactly a reappearance that is recognisable but not byte-identical.
func storedRenderProfileCard(w http.ResponseWriter, r *http.Request) {
	entries := storedSnapshot(&storedProfileMu, &storedNicknameLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Profile</h1>")
	for _, nickname := range entries {
		fmt.Fprintf(w, "<p class=\"display-name\">%s</p>", strings.ToUpper(nickname))
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Support tickets: "SQL injection (second order)"
// ---------------------------------------------------------------------------

var (
	storedSupportMu sync.Mutex
	storedTickets   []string
)

func storedSubmitTicket(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedSupportMu, &storedTickets, r.URL.Query().Get("subject"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "ticket filed\n")
}

// storedRenderTickets lists every stored subject verbatim, standing in for a listing query built
// from stored data without parameter binding.
func storedRenderTickets(w http.ResponseWriter, r *http.Request) {
	tickets := storedSnapshot(&storedSupportMu, &storedTickets)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Open tickets</h1>")
	for _, subject := range tickets {
		fmt.Fprintf(w, "<div class=\"ticket-subject\">%s</div>", subject)
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Sticky note: "Cross-site scripting (stored)"
// ---------------------------------------------------------------------------

var (
	storedNoteMu  sync.Mutex
	storedNoteLog []string
)

func storedSubmitNote(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedNoteMu, &storedNoteLog, r.URL.Query().Get("text"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "note saved\n")
}

// storedRenderNotes inlines every stored note directly into its own script statement with no
// escaping, so a value carrying a quote breaks out of the string and runs as script.
//
// The note is assigned as a bare expression rather than written into a string literal. That
// distinction is the whole point of the row: a value inside `var note = '<value>'` is correctly
// contained by the quotes, so a scanner that refuses to call it a breakout is RIGHT, and a fixture
// shaped that way cannot demonstrate stored XSS at all. Assigning the stored value as its own
// expression is what an application that concatenates user input into a script body actually does,
// and it is the shape in which a token really does reach executable position.
func storedRenderNotes(w http.ResponseWriter, r *http.Request) {
	notes := storedSnapshot(&storedNoteMu, &storedNoteLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Sticky notes</h1><script>")
	for _, n := range notes {
		fmt.Fprintf(w, "var note = 'sticky'; note = %s; console.log(note);\n", n)
	}
	fmt.Fprint(w, "</script></body></html>")
}

// ---------------------------------------------------------------------------
// Theme: "CSS injection (stored)"
// ---------------------------------------------------------------------------

var (
	storedThemeMu   sync.Mutex
	storedAccentLog []string
)

func storedSubmitTheme(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedThemeMu, &storedAccentLog, r.URL.Query().Get("accent"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "theme saved\n")
}

// storedRenderTheme inlines every stored accent colour directly into its own <style> rule with no
// validation, so a value carrying a brace closes the rule and injects further CSS (or markup, via
// a subsequent </style>).
func storedRenderTheme(w http.ResponseWriter, r *http.Request) {
	accents := storedSnapshot(&storedThemeMu, &storedAccentLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><head><style>body{background:#fff;}")
	for i, accent := range accents {
		fmt.Fprintf(w, ".accent%d{color:%s;}", i, accent)
	}
	fmt.Fprint(w, "</style></head><body><p class=\"accent\">accent applied</p></body></html>")
}

// ---------------------------------------------------------------------------
// Bookmark: "Open redirection (stored)" and "Link manipulation (stored)"
// ---------------------------------------------------------------------------

var (
	storedBookmarkMu  sync.Mutex
	storedBookmarkLog []string
)

func storedSubmitBookmark(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedBookmarkMu, &storedBookmarkLog, r.URL.Query().Get("destination"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "bookmark saved\n")
}

// storedRenderBookmarks inlines every stored destination directly into its own href with no
// validation, so a saved link can point anywhere, off-site included.
func storedRenderBookmarks(w http.ResponseWriter, r *http.Request) {
	dests := storedSnapshot(&storedBookmarkMu, &storedBookmarkLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Saved bookmarks</h1>")
	for _, dest := range dests {
		fmt.Fprintf(w, "<a href=\"%s\">your saved link</a>", dest)
	}
	fmt.Fprint(w, "</body></html>")
}

var (
	storedSafeBookmarkMu  sync.Mutex
	storedSafeBookmarkLog []string
)

func storedSubmitSafeBookmark(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedSafeBookmarkMu, &storedSafeBookmarkLog, r.URL.Query().Get("destination"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "bookmark saved\n")
}

// storedRenderSafeBookmarks mirrors safeRedirect/safeProfileLink: href only ever carries a
// validated same-origin path. Every stored value still appears, as escaped text, so a detector
// keying on reflection alone is caught here too.
func storedRenderSafeBookmarks(w http.ResponseWriter, r *http.Request) {
	dests := storedSnapshot(&storedSafeBookmarkMu, &storedSafeBookmarkLog)
	target := storedSafeTarget(dests, "/")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<!DOCTYPE html><html><body><h1>Saved bookmark</h1><a href=\"%s\">your saved link</a>", target)
	for _, dest := range dests {
		fmt.Fprintf(w, "<p>%s</p>", htmlEscape(dest))
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Workflow form: "Form action hijacking (stored)"
// ---------------------------------------------------------------------------

var (
	storedFormMu  sync.Mutex
	storedFormLog []string
)

func storedSubmitForm(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedFormMu, &storedFormLog, r.URL.Query().Get("endpoint"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "form target saved\n")
}

// storedRenderForms inlines every stored endpoint directly into its own form's action with no
// validation, so a saved workflow can submit the visitor's answers anywhere.
func storedRenderForms(w http.ResponseWriter, r *http.Request) {
	targets := storedSnapshot(&storedFormMu, &storedFormLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Saved workflows</h1>")
	for _, target := range targets {
		fmt.Fprintf(w, "<form action=\"%s\" method=\"POST\"><input name=\"answer\"><button>Submit</button></form>", target)
	}
	fmt.Fprint(w, "</body></html>")
}

var (
	storedSafeFormMu  sync.Mutex
	storedSafeFormLog []string
)

func storedSubmitSafeForm(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedSafeFormMu, &storedSafeFormLog, r.URL.Query().Get("endpoint"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "form target saved\n")
}

// storedRenderSafeForms only ever puts a validated same-origin path into the form's action,
// falling back to a fixed, local action otherwise - the workflow can never be redirected to submit
// the visitor's answers off-site.
func storedRenderSafeForms(w http.ResponseWriter, r *http.Request) {
	targets := storedSnapshot(&storedSafeFormMu, &storedSafeFormLog)
	action := storedSafeTarget(targets, "/st/forms/safe")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<!DOCTYPE html><html><body><h1>Saved workflow</h1>"+
		"<form action=\"%s\" method=\"POST\"><input name=\"answer\"><button>Submit</button></form>", action)
	for _, target := range targets {
		fmt.Fprintf(w, "<p>%s</p>", htmlEscape(target))
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Widget: "Client-side HTTP parameter pollution (stored)"
// ---------------------------------------------------------------------------

var (
	storedWidgetMu  sync.Mutex
	storedWidgetLog []string
)

func storedSubmitWidget(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedWidgetMu, &storedWidgetLog, r.URL.Query().Get("ref"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "widget preference saved\n")
}

// storedRenderWidgets concatenates every stored reference directly into its own <script src>
// query string with no URL-encoding, so a value carrying & or = adds its own parameter to the
// loaded resource.
func storedRenderWidgets(w http.ResponseWriter, r *http.Request) {
	refs := storedSnapshot(&storedWidgetMu, &storedWidgetLog)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Embedded widgets</h1>")
	for _, ref := range refs {
		fmt.Fprintf(w, "<script src=\"/widget.js?ref=%s\"></script>", ref)
	}
	fmt.Fprint(w, "</body></html>")
}

var (
	storedSafeWidgetMu  sync.Mutex
	storedSafeWidgetLog []string
)

func storedSubmitSafeWidget(w http.ResponseWriter, r *http.Request) {
	storedAppend(&storedSafeWidgetMu, &storedSafeWidgetLog, r.URL.Query().Get("ref"))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "widget preference saved\n")
}

// storedRenderSafeWidgets only ever uses a validated same-origin path as the script's src, never a
// query string built from the raw reference - the value can no longer add a parameter to anything,
// because it never becomes part of a URL's query component at all.
func storedRenderSafeWidgets(w http.ResponseWriter, r *http.Request) {
	refs := storedSnapshot(&storedSafeWidgetMu, &storedSafeWidgetLog)
	src := storedSafeTarget(refs, "/widget.js")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<!DOCTYPE html><html><body><h1>Embedded widget</h1><script src=\"%s\"></script>", src)
	for _, ref := range refs {
		fmt.Fprintf(w, "<p>%s</p>", htmlEscape(ref))
	}
	fmt.Fprint(w, "</body></html>")
}
