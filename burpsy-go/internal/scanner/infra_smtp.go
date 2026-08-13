package scanner

import "strings"

// SMTP mail-header injection primitive, corresponding to the declined catalog row
// "SMTP header injection" (2099200 / burp.Zf8g.APIP_SmtpHeaderInjection, dispatched
// by burp.Zgcg).
//
// Evidence recovered from Zgcg: grep of /root/burp-re/out/strings/map_root.tsv for
// "^burp.Zgcg\t" and a read of /root/burp-re/out/clean/root/Zgcg.java yields exactly
// two literals, "user-agent" and "referer" — both used only to skip probing those
// two insertion points (they are attacker-uncontrolled or already covered by other
// checks), not payload material. Zgcg's actual probe generation is delegated to a
// shared engine (this.ZB.Zn(this.ZV), reached through burp.Zrok/Ze2n) whose own
// literal payload arrays are ZKM ciphertext residue in this decompilation, so no
// Burp-specific separator or header-splice string is recoverable for this class.
// Every payload string below is therefore a documented, industry-standard SMTP/CRLF
// header-injection technique (RFC 5321/5322 line folding via bare CR/LF, and the
// well-known percent-encoding / pre-decoded bypasses used against proxies and
// frameworks that decode a query value before handing it to a mail header builder),
// not a value recovered from Burp's own source.
//
// IMPORTANT LIMIT: this primitive only has the request-and-response half of the
// oracle. A real SMTP header injection (e.g. a forged Bcc: line reaching a mail
// transfer agent) is only conclusively proven by an out-of-band mailbox actually
// receiving the injected message — this package has no mailbox to check. A caller
// that gets EvidenceNone back MUST treat that as "no signal was visible in the HTTP
// exchange", never as "no SMTP injection exists": the separator may still have
// reached the mail layer with no visible trace in the response.
type MailInjectionEvidence uint8

const (
	// MailInjectionNone is the zero value: nothing in the response distinguished
	// the probe from the baseline. See the file-level limit above.
	MailInjectionNone MailInjectionEvidence = 0

	// MailInjectionReflectedVerbatim means the payload (including its separator)
	// came back unchanged in the response body. The app treats the value as inert
	// text; this is evidence AGAINST injection, not for it.
	MailInjectionReflectedVerbatim MailInjectionEvidence = 1 << (iota - 1)

	// MailInjectionSeparatorStripped means the payload reflected but with the CR/LF
	// (or its encoded form) removed or collapsed — the app is actively sanitising
	// header-breaking bytes before using the value.
	MailInjectionSeparatorStripped

	// MailInjectionMailLibraryError means a recognisable mail-library error string
	// surfaced in the probe response. This is the strong signal: it means the raw
	// separator (or its decoded form) reached code that tried to parse the value as
	// a mail header/address and rejected it, which only happens if the header split
	// actually occurred.
	MailInjectionMailLibraryError

	// MailInjectionStatusOrBodyDivergence means the probe response's status code or
	// body differs from the baseline with no recognised error text and no verbatim
	// reflection. This is a weak signal only — plenty of unrelated causes (session
	// state, rate limiting, timing) produce the same observation.
	MailInjectionStatusOrBodyDivergence
)

// MailHeaderInjection is one probe in the separator x encoding matrix: a
// fully-formed value meant to be substituted into an attacker-controlled request
// field (e.g. a "name" or "email" parameter that a server-side mail composer later
// folds into a header) that, if the separator survives to the mail layer, splices
// an extra "Bcc: <canary>@example.invalid" header into the outgoing message.
type MailHeaderInjection struct {
	// Payload is the full value to submit: <marker><encoded-separator>Bcc:
	// <canary>@example.invalid
	Payload string
	// InjectedHeader is the raw (unencoded) header line the payload attempts to
	// splice in, e.g. "Bcc: abc123@example.invalid". Useful for a caller building
	// a mail-library-error match or a report string without re-deriving it.
	InjectedHeader string
	// Separator is the raw (unencoded) line terminator under test: "\r\n", "\n", or
	// "\r".
	Separator string
	// Encoding names which of the three encodings produced Payload: "raw",
	// "percent", or "percent-predecoded".
	Encoding string
}

// mailHeaderSeparators mirrors headerInjectionSeparators in checks_reflection2.go:
// the three line-terminator variants RFC 5322 header folding recognises. Kept as a
// separate slice (rather than importing the other file's package-level var) so this
// file's probe matrix is self-contained and doesn't silently break if that slice's
// order or contents change for its own (generic header injection) purposes.
var mailHeaderSeparators = [...]string{"\r\n", "\n", "\r"}

// mailHeaderEncodings names the three encodings in MailHeaderPayloads, in the order
// they are generated. "percent-predecoded" is not part of encodeHeaderInjectionSeparator's
// bit-flag scheme (that function only knows raw vs. percent vs. NUL-prefixed); it is
// a distinct, mail-injection-specific technique: submitting "%0d%0a" literally so
// that a component which performs exactly one URL-decode pass before composing the
// mail header (common in PHP mail() wrappers and older Java servlets that decode
// query params once) ends up with a raw CRLF it never intended to accept, even when
// the same component's own input validation rejects a raw CR/LF submitted directly.
const (
	mailEncodingRaw            = "raw"
	mailEncodingPercent        = "percent"
	mailEncodingPercentDoubled = "percent-double-encoded"
)

// percentDoubleEncodedSeparator returns the double-percent-encoded form of sep, e.g.
// "%250d%250a" for CRLF: percent-encoding applied twice, so that ONE decode pass
// yields "%0d%0a" and a SECOND pass yields the raw separator.
//
// This is the encoding that survives a component which URL-decodes on top of whatever
// the transport already decoded — a mail-composing layer behind a framework that has
// itself already decoded the parameter once. It must not be confused with
// encodeHeaderInjectionSeparator(sep, 1), which is single percent-encoding: that is
// undone by the transport alone and therefore reaches the application as the raw
// separator, testing a different defence entirely.
//
// An earlier revision of this function returned percentEncodeNonAlnum(sep) directly,
// which made it byte-identical to variant 1 and silently collapsed the 3x3 probe matrix
// to 6 distinct payloads while the doc comment still claimed 9. The distinctness test in
// infra_smtp_test.go exists to keep that from recurring.
func percentDoubleEncodedSeparator(sep string) string {
	return strings.ReplaceAll(percentEncodeNonAlnum(sep), "%", "%25")
}

// MailHeaderPayloads builds the SMTP header-injection probe matrix: for each of the
// three separators, three encodings (raw, single percent-encoded, and double
// percent-encoded — see percentDoubleEncodedSeparator), splicing a "Bcc: <canary>@example.invalid" header
// after the separator. canary should be unique per scan so a later mailbox check (if
// one is ever wired up) can correlate a delivered message back to this exact probe;
// within a single call the same canary is reused across all 9 payloads because the
// separator/encoding is the only variable under test.
//
// The raw encoding reuses encodeHeaderInjectionSeparator(sep, 0) — i.e. sep
// untouched — rather than duplicating that no-op, so this function and
// checkHeaderInjection agree on what "raw" means for a shared separator set.
func MailHeaderPayloads(canary string) []MailHeaderInjection {
	if canary == "" {
		canary = newProbeCanary("smtp")
	}
	injectedHeader := "Bcc: " + canary + "@example.invalid"

	encoders := [...]struct {
		name string
		fn   func(sep string) string
	}{
		{mailEncodingRaw, func(sep string) string { return encodeHeaderInjectionSeparator(sep, 0) }},
		{mailEncodingPercent, func(sep string) string { return encodeHeaderInjectionSeparator(sep, 1) }},
		{mailEncodingPercentDoubled, percentDoubleEncodedSeparator},
	}

	payloads := make([]MailHeaderInjection, 0, len(mailHeaderSeparators)*len(encoders))
	for _, sep := range mailHeaderSeparators {
		for _, enc := range encoders {
			encodedSep := enc.fn(sep)
			payloads = append(payloads, MailHeaderInjection{
				Payload:        canary + encodedSep + injectedHeader,
				InjectedHeader: injectedHeader,
				Separator:      sep,
				Encoding:       enc.name,
			})
		}
	}
	return payloads
}

// mailLibraryErrorSignatures are substrings of real error messages raised by
// mainstream mail libraries when they reject or choke on a malformed header/address
// caused by an embedded CR/LF. Matching one of these in a response body is a strong
// signal that the injected separator reached the mail-composition layer (rather than
// merely being reflected as inert text), because these exceptions are specific to
// address/header parsing, not generic error pages.
var mailLibraryErrorSignatures = [...]string{
	// PHP mail(): the built-in mail() function and common wrappers (PHPMailer,
	// SwiftMailer) surface warnings referencing the function name or "additional
	// headers" when a header value contains a stray CR/LF.
	"mail(): Multiple or malformed newlines found in additional_headers",
	"Warning: mail()",
	"PHPMailer",
	// Java javax.mail / Jakarta Mail (the javax->jakarta namespace rename kept the
	// exception class name and message shape identical).
	"javax.mail.MessagingException",
	"jakarta.mail.MessagingException",
	"AddressException",
	// Python smtplib.
	"smtplib.SMTPException",
	"SMTPNotSupportedError",
	"SMTPRecipientsRefused",
	// .NET System.Net.Mail.
	"System.Net.Mail.SmtpException",
	"FormatException: The specified string is not in the form required for an e-mail address",
}

// ClassifyMailHeaderResponse decides what a probe response revealed about SMTP
// header injection, given only the request-side observation (see the file-level
// doc comment for why this can never be conclusive proof of a delivered forged
// header). baselineBody/baselineStatus are the unmodified request's response;
// probeBody/probeStatus are the same request with one MailHeaderInjection payload
// substituted into the vulnerable field.
func ClassifyMailHeaderResponse(baselineBody, probeBody string, baselineStatus, probeStatus int) MailInjectionEvidence {
	lowerProbe := strings.ToLower(probeBody)
	lowerBaseline := strings.ToLower(baselineBody)

	// Mail-library error text is the strongest signal available and takes
	// priority over the weaker reflection heuristics below: an app can echo an
	// input validation error (containing fragments of the payload) at the same
	// time it surfaces the underlying mail-layer exception.
	for _, sig := range mailLibraryErrorSignatures {
		lowerSig := strings.ToLower(sig)
		if strings.Contains(lowerProbe, lowerSig) && !strings.Contains(lowerBaseline, lowerSig) {
			return MailInjectionMailLibraryError
		}
	}

	if probeBody == baselineBody && probeStatus == baselineStatus {
		return MailInjectionNone
	}

	// "Bcc: " reaching the response body at all means the injected header text
	// made it through in some form. Whether the CR/LF-family separator survived
	// immediately in front of it distinguishes literal reflection (the whole
	// payload printed back as inert text — evidence AGAINST a real split) from
	// stripped/sanitised separators (the app defused the break but still leaked
	// the trailing header text).
	if strings.Contains(probeBody, mailInjectedHeaderMarker) {
		if bodyHasUnstrippedSeparatorBeforeMarker(probeBody) {
			return MailInjectionReflectedVerbatim
		}
		return MailInjectionSeparatorStripped
	}

	// Neither a library error nor any trace of the injected header text, but the
	// response still diverged from baseline: a weak signal only, per the file
	// header's limit — this could equally be unrelated request/response noise.
	return MailInjectionStatusOrBodyDivergence
}

// mailInjectedHeaderMarker is the fixed header-name fragment every
// MailHeaderPayloads probe splices in, used to recognise the injected text
// landing in a response body regardless of which separator/encoding carried it.
const mailInjectedHeaderMarker = "Bcc: "

// mailSeparatorVariants enumerates every raw/encoded form MailHeaderPayloads can
// produce for the three separators, so bodyHasUnstrippedSeparatorBeforeMarker can
// recognise a fully-reflected payload under any of the three encodings.
func mailSeparatorVariants() []string {
	variants := make([]string, 0, len(mailHeaderSeparators)*2)
	for _, sep := range mailHeaderSeparators {
		variants = append(variants, sep, percentDoubleEncodedSeparator(sep))
	}
	return variants
}

// bodyHasUnstrippedSeparatorBeforeMarker reports whether body contains one of the
// separator encodings immediately followed by the injected-header marker — i.e.
// the payload's separator survived intact right next to "Bcc: ", which is what a
// verbatim, unmodified reflection of the whole payload looks like.
func bodyHasUnstrippedSeparatorBeforeMarker(body string) bool {
	for _, sep := range mailSeparatorVariants() {
		if sep == "" {
			continue
		}
		if strings.Contains(body, sep+mailInjectedHeaderMarker) {
			return true
		}
	}
	return false
}

// Text renders the detected mail-injection evidence classes as prose, in order
// from strongest to weakest signal, mirroring corsEvidenceText/cspEvidenceText's
// shape in checks_headers.go.
func (e MailInjectionEvidence) Text() string {
	if e == MailInjectionNone {
		return "no SMTP header injection signal was visible in the HTTP exchange (this does not rule out injection reaching an unobserved mail layer)"
	}
	var parts []string
	if e&MailInjectionMailLibraryError != 0 {
		parts = append(parts, "a mail-library error surfaced in the probe response, indicating the injected separator reached the mail-composition layer")
	}
	if e&MailInjectionSeparatorStripped != 0 {
		parts = append(parts, "the injected separator was stripped or sanitised before the header text was echoed")
	}
	if e&MailInjectionReflectedVerbatim != 0 {
		parts = append(parts, "the payload was reflected verbatim, including its separator, as inert text — evidence against a real header split")
	}
	if e&MailInjectionStatusOrBodyDivergence != 0 {
		parts = append(parts, "the response diverged from the baseline with no error text and no verbatim reflection (a weak signal only)")
	}
	return strings.Join(parts, "; ")
}
