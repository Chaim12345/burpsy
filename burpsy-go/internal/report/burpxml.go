package report

import (
	"encoding/base64"
	"html"
	"strconv"
	"strings"
	"time"
)

// The Burp-XML issue export (burpsy-react-ui-m7dk).
//
// Burp's desktop can "export issue data in XML format … useful if you want to
// import information about issues into other tools or reporting frameworks"
// (desktop/running-scans/reporting/report-settings.html), and that export is a
// fixed shape: an internal DTD, a small element set per issue, and Base64
// request/response pairs. Tooling that ingests it keys on that shape, not on
// anything burpsy could invent — so this file reproduces Burp's grammar rather
// than approximating it.
//
// Ground truth (Burp Suite 2026.7.1, decompiled under /root/burp-re):
//   - burp/Zb2g.java — the issue writer: the DTD literal (ZI), the per-issue
//     element sequence (Zk: serialNumber, type, name, host ip="…", path,
//     location, severity, confidence), the optional detail elements each gated
//     by a wizard setting (Zx/ZQ/Zq/ZI/ZU/ZG), and the 2-space indent writer
//     (Zxke) with \r\n line ends.
//   - burp/Zpa6.java — requestresponse: one element per evidence pair, request
//     before response, bytes truncated at the configured maximum length BEFORE
//     Base64, and the element omitted entirely when neither half is present.
//   - burp/Zcus.java:23 — exportTime is Java's Date.toString(), i.e. the
//     "EEE MMM dd HH:mm:ss zzz yyyy" shape.
//   - burp/Ze1r.java / burp/Zeue.java — Burp's severity and confidence
//     vocabularies for the two same-named elements.
//   - report-settings.html — "The path element contains the URL for the issue.
//     It excludes the query string."

// burpXMLDTD is the internal DTD Burp's own export writes, byte-for-byte from
// burp.Zb2g.ZI. Embedded verbatim rather than simplified: a consumer that
// validates against the DTD validates against Burp's grammar, and a trimmed
// subset would be a different format wearing the same name. burpsy never emits
// the collaboratorEvent / infiltratorEvent / staticAnalysis / dynamicAnalysis /
// prototypePollution / smtp elements — they describe Burp-side features burpsy
// does not have — but the DTD declares them because that is the format.
//
// Line ends: Burp writes the whole document with \r\n (Zxke appends "\r\n" to
// every line). The const below uses plain newlines so it stays diffable; the
// writer translates at output time.
const burpXMLDTD = `<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "">
<!ATTLIST issues exportTime CDATA "">
<!ELEMENT issue (serialNumber, type, name, host, path, location, severity, confidence, issueBackground?, remediationBackground?, references?, vulnerabilityClassifications?, issueDetail?, issueDetailItems?, remediationDetail?, requestresponse*, collaboratorEvent*, infiltratorEvent*, staticAnalysis*, dynamicAnalysis*, prototypePollution*)>
<!ELEMENT serialNumber (#PCDATA)>
<!ELEMENT type (#PCDATA)>
<!ELEMENT name (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT path (#PCDATA)>
<!ELEMENT location (#PCDATA)>
<!ELEMENT severity (#PCDATA)>
<!ELEMENT confidence (#PCDATA)>
<!ELEMENT issueBackground (#PCDATA)>
<!ELEMENT remediationBackground (#PCDATA)>
<!ELEMENT references (#PCDATA)>
<!ELEMENT vulnerabilityClassifications (#PCDATA)>
<!ELEMENT issueDetail (#PCDATA)>
<!ELEMENT issueDetailItems (issueDetailItem*)>
<!ELEMENT issueDetailItem (#PCDATA)>
<!ELEMENT remediationDetail (#PCDATA)>
<!ELEMENT requestresponse (request?, response?, responseRedirected?)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request method CDATA "">
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT responseRedirected (#PCDATA)>
<!ELEMENT sender (#PCDATA)>
<!ELEMENT message (#PCDATA)>
<!ELEMENT conversation (#PCDATA)>
<!ELEMENT recipient (#PCDATA)>
<!ELEMENT recipients (recipient*)>
<!ELEMENT smtp (sender, recipients, message, conversation)>
<!ELEMENT collaboratorEvent (interactionType, originIp, time, lookupType?, lookupHost?, requestresponse?, smtp?)>
<!ELEMENT interactionType (#PCDATA)>
<!ELEMENT originIp (#PCDATA)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT lookupType (#PCDATA)>
<!ELEMENT lookupHost (#PCDATA)>
<!ELEMENT infiltratorEvent (parameterName, platform, signature, stackTrace?, parameterValue?, collaboratorEvent)>
<!ELEMENT parameterName (#PCDATA)>
<!ELEMENT platform (#PCDATA)>
<!ELEMENT signature (#PCDATA)>
<!ELEMENT stackTrace (#PCDATA)>
<!ELEMENT parameterValue (#PCDATA)>
<!ELEMENT dynamicAnalysis (source, sink, sourceStackTrace, sinkStackTrace, eventListenerStackTrace, sourceValue, sinkValue, eventHandlerData, eventHandlerDataType, eventHandlerManipulatedData, poc, origin, isOriginChecked, sourceElementId, sourceElementName, eventFiredEventName, eventFiredElementId, eventFiredElementName, eventFiredOuterHtml)>
<!ELEMENT prototypePollution (poc, pollutionTechnique, pollutionType)>
<!ELEMENT staticAnalysis (source, sink, codeSnippets)>
<!ELEMENT source (#PCDATA)>
<!ELEMENT sink (#PCDATA)>
<!ELEMENT sourceStackTrace (#PCDATA)>
<!ELEMENT sinkStackTrace (#PCDATA)>
<!ELEMENT eventListenerStackTrace (#PCDATA)>
<!ELEMENT sourceValue (#PCDATA)>
<!ELEMENT sinkValue (#PCDATA)>
<!ELEMENT eventHandlerData (#PCDATA)>
<!ELEMENT eventHandlerDataType (#PCDATA)>
<!ELEMENT sourceElementId (#PCDATA)>
<!ELEMENT sourceElementName (#PCDATA)>
<!ELEMENT eventFiredEventName (#PCDATA)>
<!ELEMENT eventFiredElementId (#PCDATA)>
<!ELEMENT eventFiredElementName (#PCDATA)>
<!ELEMENT eventFiredOuterHtml (#PCDATA)>
<!ELEMENT eventHandlerManipulatedData (#PCDATA)>
<!ELEMENT poc (#PCDATA)>
<!ELEMENT origin (#PCDATA)>
<!ELEMENT isOriginChecked (#PCDATA)>
<!ELEMENT codeSnippets (codeSnippet*)>
<!ELEMENT codeSnippet (#PCDATA)>
<!ELEMENT pollutionTechnique (#PCDATA)>
<!ELEMENT pollutionType (#PCDATA)>
]>`

// extensionGeneratedTypeIndex is Burp's index for issues its catalogue does
// not describe — 0x08000000, "Extension generated issue" (the catalogue file
// 08000000_ExtensionGeneratedIssue.json carries the same number). It is the
// value Burp itself uses for out-of-catalogue issues, so a burpsy finding with
// no catalogue entry takes it rather than an invented number; the issue
// element carries a comment saying the substitution happened.
const extensionGeneratedTypeIndex = 134217728

// BurpXML renders rows in Burp's issue-data XML export format.
//
// Messages ride the document only when the caller attached them to the rows
// (Row.Messages): the route decides mode and length, this writer decides
// shape. Base64 is always the encoding used — base64="false" exists in the
// DTD because Burp offers it, but Burp's own export notes that mode leaves
// NULL bytes that "strictly break the XML syntax" and recommends Base64 for
// strict parsers; a byte-exact message cannot ride an XML text node at all,
// so burpsy does not offer the lossy variant. Every requestresponse therefore
// declares base64="true" and the bytes decode back exactly.
//
// st.MessageMode is read for one thing only: whether the caller was asked
// for messages at all. An evidence entry whose bytes could not be read is
// commented rather than skipped when messages were requested ("you asked, and
// this one is missing"), and left out entirely when they were not (an opt-out
// is not a hole, and peppering it with "no readable bytes" comments would say
// the capture failed where the operator simply declined).
//
// Rows keep the caller's order: Burp exports the collection it was handed,
// and burpsy's report rows arrive already filtered by the route.
func BurpXML(rows []Row, st Settings, exportedAt time.Time) []byte {
	var b strings.Builder
	// base64 mode is the only mode (see the doc comment), so the declaration
	// is 1.0 — Burp writes 1.1 only for the NULL-byte-preserving variant.
	b.WriteString("<?xml version=\"1.0\"?>\r\n")
	b.WriteString(strings.ReplaceAll(burpXMLDTD, "\n", "\r\n"))
	b.WriteString("\r\n")
	b.WriteString(`<issues burpVersion="` + xmlAttrValue("burpsy") + `" exportTime="` +
		xmlAttrValue(exportedAt.Format("Mon Jan 02 15:04:05 MST 2006")) + `">` + "\r\n")
	for i := range rows {
		writeBurpIssue(&b, &rows[i], st)
	}
	b.WriteString("</issues>\r\n")
	return []byte(b.String())
}

// writeBurpIssue writes one <issue> element. Element order is the DTD's, not
// a convenient one: serialNumber through confidence are required and the
// optional detail elements follow in their declared sequence, so a validating
// consumer sees the grammar it expects.
func writeBurpIssue(b *strings.Builder, f *Row, st Settings) {
	b.WriteString("  <issue>\r\n")
	b.WriteString("    <serialNumber>" + strconv.FormatUint(f.ID, 10) + "</serialNumber>\r\n")

	typeIndex, fromCatalogue := burpIssueType(*f)
	if !fromCatalogue {
		// The finding resolved to no catalogue entry, so its type is the
		// extension-generated index rather than a number pulled from
		// anywhere. Said out loud in a comment because a consumer that
		// tallies issue types deserves to know which values are real
		// catalogue indexes and which are this substitution. Static text
		// only — XML comments cannot contain "--", and the finding's name
		// is attacker-influenced, so it does not go inside the comment.
		b.WriteString("    <!-- no issue-definition catalogue entry; type 134217728 (0x08000000, Extension generated issue) substituted -->\r\n")
	}
	b.WriteString("    <type>" + strconv.FormatInt(int64(typeIndex), 10) + "</type>\r\n")

	// The DTD's required elements are written even when empty: serialNumber
	// through confidence have no "?" in the content model, so skipping one
	// would make the document invalid for every consumer that validates —
	// including xmllint here. An empty element says "no value", which is the
	// truth, where a missing one says "no element", which is a broken file.
	writeRequiredXMLElement(b, "name", f.Name)
	host := burpIssueHost(*f)
	b.WriteString(`    <host ip="">` + xmlText(host) + "</host>\r\n")
	writeRequiredXMLElement(b, "path", stripQuery(burpIssuePath(*f)))
	writeRequiredXMLElement(b, "location", burpIssueLocation(*f))
	writeRequiredXMLElement(b, "severity", f.Severity)
	writeRequiredXMLElement(b, "confidence", f.Confidence)

	// The catalogue's standard text, which Burp writes as the issueBackground
	// and remediationBackground ("the standard description … the same for all
	// issues of the same type" — report-settings.html). Burp strips the HTML
	// (Zb2g passes every text element through net.portswigger.Zhs.Zq); the
	// fragments burpsy holds are already SanitisedHTML output, so the tag
	// strip below recovers the plain text.
	//
	// The sections gate these the same way Burp's wizard does — its XML
	// writer reads the same issue-details settings (Zb2g's Zxcm flags) —
	// with burpsy's four names mapping onto Burp's toggles: background is
	// the catalogue block, classifications the link lists, detail and
	// remediation the finding's own text.
	if f.Advisory != nil && st.sectionOn("background") {
		if text := sanitisedHTMLToText(f.Advisory.DescriptionHTML); text != "" {
			writeXMLElement(b, "issueBackground", text)
		}
		if text := sanitisedHTMLToText(f.Advisory.RemediationHTML); text != "" {
			writeXMLElement(b, "remediationBackground", text)
		}
	}
	if f.Advisory != nil && st.sectionOn("classifications") {
		if lines := linkLines(f.Advisory.References); lines != "" {
			writeXMLElement(b, "references", lines)
		}
		if lines := linkLines(f.Advisory.Classifications); lines != "" {
			writeXMLElement(b, "vulnerabilityClassifications", lines)
		}
	}
	// The finding's own text is the per-instance detail — Burp's "Issue
	// detail" is "specific information about the issue", distinct from the
	// standard background above.
	if st.sectionOn("detail") && f.Description != "" {
		writeXMLElement(b, "issueDetail", f.Description)
	}
	if st.sectionOn("remediation") && f.Remediation != "" {
		writeXMLElement(b, "remediationDetail", f.Remediation)
	}

	writeBurpRequestResponses(b, f, st)
	b.WriteString("  </issue>\r\n")
}

// writeBurpRequestResponses writes one requestresponse element per evidence
// entry that has bytes attached, request before response — the DTD's order.
// Entries whose bytes are missing get a comment, not silence, when messages
// were requested: a capture whose evidence could not be read must not export
// as "there was no request". When the caller asked for no messages at all
// (MessageMode none) the entries are skipped without comment — an opt-out
// reads as an opt-out, not as a capture failure.
func writeBurpRequestResponses(b *strings.Builder, f *Row, st Settings) {
	for i := range f.Evidence {
		var req, resp *AttachedMessage
		for j := range f.Messages {
			if f.Messages[j].Evidence != i {
				continue
			}
			if f.Messages[j].IsRequest {
				req = &f.Messages[j]
			} else {
				resp = &f.Messages[j]
			}
		}
		if req == nil && resp == nil {
			if (st.MessageMode == "full" || st.MessageMode == "relevant") &&
				(f.Evidence[i].HasRequest || f.Evidence[i].HasResponse) {
				b.WriteString("    <!-- evidence " + strconv.Itoa(i) +
					": no readable request/response bytes in the capture -->\r\n")
			}
			continue
		}
		b.WriteString("    <requestresponse>\r\n")
		if req != nil {
			b.WriteString(`      <request method="` + xmlAttrValue(f.Evidence[i].Method) + `" base64="true">`)
			b.WriteString(base64.StdEncoding.EncodeToString(req.Raw))
			b.WriteString("</request>\r\n")
		}
		if resp != nil {
			b.WriteString(`      <response base64="true">`)
			b.WriteString(base64.StdEncoding.EncodeToString(resp.Raw))
			b.WriteString("</response>\r\n")
		}
		b.WriteString("    </requestresponse>\r\n")
	}
}

// burpIssueType returns the issue's numeric type and whether it came from the
// catalogue. The catalogue index is carried on Row.Advisory as Burp's own hex
// form (advisory.Definition.HexIndex, "00100200"); parsing it back to the
// integer the <type> element wants keeps one representation in transit and
// the exact number in the file.
func burpIssueType(f Row) (index int, fromCatalogue bool) {
	if f.Advisory == nil {
		return extensionGeneratedTypeIndex, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(f.Advisory.TypeIndex), 16, 32)
	if err != nil {
		// HexIndex always produces 8 hex digits, so this cannot happen
		// through the API — but an advisory with an unparseable index is
		// reported as one rather than exported as a lie.
		return extensionGeneratedTypeIndex, false
	}
	return int(v), true
}

// burpIssueHost is the host element's content: the first location the finding
// was observed at, falling back to the merged host list. burpsy merges
// same-issue observations across hosts into one row where Burp would hold one
// issue per host; the first host leads and the requestresponse list still
// carries every occurrence's bytes. See gaps.md.
func burpIssueHost(f Row) string {
	if len(f.Evidence) > 0 && f.Evidence[0].Host != "" {
		return f.Evidence[0].Host
	}
	if len(f.Hosts) > 0 {
		return f.Hosts[0]
	}
	return ""
}

// burpIssuePath is the path element's content: the URL path, query string
// excluded — Burp's documented rule for this element. burpsy's capture store
// keeps the query in the exchange path, so it is cut here rather than at
// capture time, where the history UI still shows the full target.
func burpIssuePath(f Row) string {
	if len(f.Evidence) > 0 {
		return f.Evidence[0].Path
	}
	return ""
}

// stripQuery removes the query string from a request target, per the path
// element's contract.
func stripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// burpIssueLocation describes the entry point: where the finding was observed
// and, when the finding names inputs, which ones — Burp's location element
// "may contain a specific URL parameter, or a request header". burpsy's rows
// carry the parameter set rather than a per-issue location string, so the two
// are joined here in Burp's "[parameters]" shape.
//
// Unlike the path element, location keeps the query string: the two elements
// have different contracts — path is documented as "the URL for the issue …
// excluding the query string", while location is the entry-point description,
// and a finding observed at /login?user=x is described by that whole target.
func burpIssueLocation(f Row) string {
	loc := burpIssueHost(f) + burpIssuePath(f)
	if len(f.Params) > 0 {
		loc += " [" + strings.Join(f.Params, ", ") + "]"
	}
	return loc
}

// linkLines renders the advisory's references or classifications as one
// "Title: URL" line each. Burp's element is PCDATA — plain text — and the
// consumer that reads it wants to know what to look at, which a bare URL list
// or a bare title list each only half say.
func linkLines(links []Link) string {
	if len(links) == 0 {
		return ""
	}
	lines := make([]string, 0, len(links))
	for _, l := range links {
		if l.URL == "" {
			lines = append(lines, l.Title)
			continue
		}
		lines = append(lines, l.Title+": "+l.URL)
	}
	return strings.Join(lines, "\n")
}

// writeRequiredXMLElement writes one of the DTD's required text elements,
// empty or not — see writeBurpIssue for why omitting one is a broken file.
func writeRequiredXMLElement(b *strings.Builder, name, content string) {
	b.WriteString("    <" + name + ">" + xmlText(content) + "</" + name + ">\r\n")
}

// writeXMLElement writes one of the DTD's optional text elements, or nothing
// at all for empty content. Burp's writer emits the optional elements only
// when they carry something (Zb2g: each detail element is written behind its
// own null check); an empty <issueBackground></issueBackground> pair would
// read as a value where there is none.
func writeXMLElement(b *strings.Builder, name, content string) {
	if content == "" {
		return
	}
	b.WriteString("    <" + name + ">" + xmlText(content) + "</" + name + ">\r\n")
}

// xmlText escapes a string for XML element content: the four characters that
// would leave the text grammar (& < >, and the CR that a parser normalises to
// LF). Literal LF and tab survive, because XML content preserves them —
// escaping them would make multi-line details unreadable for no correctness
// gain. ">" is escaped too, which is also what breaks a "]]>" sequence: the
// one string XML forbids in content even after the other escapes.
func xmlText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// xmlAttrValue escapes a string for a double-quoted attribute value. Attribute
// values undergo normalisation that element content does not: a literal tab,
// LF or CR becomes a space, so the three are written as character references
// to survive the parse. " and & close or open entities and are escaped as a
// matter of grammar; < and > are escaped because an attribute containing
// markup-shaped text must not become markup when a naive consumer inlines it.
func xmlAttrValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitisedHTMLToText strips the markup from an advisory.SanitisedHTML
// fragment and unescapes the entities, yielding the plain text Burp's XML
// elements carry.
//
// It is a tag scanner, not an HTML parser, and it is safe only because its
// input grammar is already the sanitiser's: allowed elements only, NO
// attributes, no comments, no script — so a "<" is always the start of a
// whitelisted tag and a ">" always ends it. Pointing it at anything wider
// would be an HTML parser written in IndexByte, which is exactly the bug this
// doc comment exists to prevent. The report package stays stdlib-only by
// not importing the sanitiser's x/net/html; the trade is this function's
// narrow contract, stated here.
//
// Block closers end a line so paragraphs stay paragraphs: "<p>a</p><p>b</p>"
// is "a\nb", not "ab".
func sanitisedHTMLToText(fragment string) string {
	var b strings.Builder
	for {
		lt := strings.IndexByte(fragment, '<')
		if lt == -1 {
			b.WriteString(fragment)
			break
		}
		gt := strings.IndexByte(fragment[lt:], '>')
		if gt == -1 {
			// The sanitiser never emits an unbalanced tag; keeping the tail
			// as text is the degrade-to-visible behaviour if one appears.
			b.WriteString(fragment)
			break
		}
		b.WriteString(fragment[:lt])
		tag := fragment[lt+1 : lt+gt]
		switch {
		case tag == "br":
			b.WriteByte('\n')
		case strings.HasPrefix(tag, "/") && blockClosers[tag[1:]]:
			b.WriteByte('\n')
		}
		fragment = fragment[lt+gt+1:]
	}
	return strings.TrimSpace(html.UnescapeString(b.String()))
}

// blockClosers are the sanitiser's allowed elements that end a block of text.
var blockClosers = map[string]bool{
	"p": true, "li": true, "ul": true, "ol": true, "pre": true,
	"h4": true, "h5": true, "h6": true,
}
