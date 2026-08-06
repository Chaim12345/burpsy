package advisory

import (
	"html"
	"strings"

	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// SanitisedHTML renders a definition's Description or Remediation as markup safe to embed.
//
// The package doc has promised this function since the catalogue was added; until now it did not
// exist, so every consumer either escaped the fragments (losing the paragraph structure that is the
// difference between readable remediation advice and a wall of text) or would have had to trust them
// verbatim. This is the missing third option.
//
// # Why sanitise content that ships in the binary
//
// The catalogue is PortSwigger's own text, embedded at build time — it is not attacker-controlled,
// and on today's inputs this function has nothing to remove. It exists for the two ways that changes
// without anyone revisiting the renderers: an operator-supplied catalogue directory (the documented
// swap if the embed is ever dropped), and a future definition that carries markup nobody audited. A
// report is a file that gets mailed around and opened outside the tool, so the safe default belongs
// at the rendering seam rather than in an assumption about the corpus.
//
// # What survives
//
// Structural and inline-emphasis elements only, and no attributes at all — not even href, because a
// link is not needed to render an advisory and `javascript:` targets are exactly the thing this is
// here to stop. References and classifications are carried as their own typed fields with their own
// URLs, so the caller renders those as real links from data it can check, rather than from markup.
//
// Anything not on the list is dropped as an element while its text is kept, so removing a tag never
// silently removes the sentence inside it. Text is escaped, so a fragment that is not valid HTML
// degrades to visible text rather than to injected markup.
var allowedElements = map[atom.Atom]bool{
	atom.P:      true,
	atom.Br:     true,
	atom.Ul:     true,
	atom.Ol:     true,
	atom.Li:     true,
	atom.B:      true,
	atom.Strong: true,
	atom.I:      true,
	atom.Em:     true,
	atom.Code:   true,
	atom.Pre:    true,
	atom.H4:     true,
	atom.H5:     true,
	atom.H6:     true,
}

// voidElements are allowed elements that must not be given a closing tag.
var voidElements = map[atom.Atom]bool{atom.Br: true}

// SanitisedHTML returns the fragment with only allow-listed elements and no attributes, text escaped.
// The return is a plain string rather than template.HTML so that callers have to make the decision to
// trust it explicitly at their own boundary, where it is visible in review.
func SanitisedHTML(fragment string) string {
	if strings.TrimSpace(fragment) == "" {
		return ""
	}
	nodes, err := xhtml.ParseFragment(strings.NewReader(fragment), &xhtml.Node{
		Type:     xhtml.ElementNode,
		Data:     "body",
		DataAtom: atom.Body,
	})
	if err != nil {
		// Unparseable input degrades to escaped text: visible and inert, never markup.
		return html.EscapeString(fragment)
	}
	var b strings.Builder
	for _, n := range nodes {
		writeSanitised(&b, n)
	}
	return b.String()
}

func writeSanitised(b *strings.Builder, n *xhtml.Node) {
	switch n.Type {
	case xhtml.TextNode:
		b.WriteString(html.EscapeString(n.Data))
		return
	case xhtml.ElementNode:
		if allowedElements[n.DataAtom] {
			b.WriteByte('<')
			b.WriteString(n.Data)
			b.WriteByte('>')
			if voidElements[n.DataAtom] {
				// A void element has no children and no closing tag; emitting one would be invalid.
				return
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				writeSanitised(b, c)
			}
			b.WriteString("</")
			b.WriteString(n.Data)
			b.WriteByte('>')
			return
		}
		// Not allowed: drop the tag, keep what it wrapped, so no sentence disappears with its element.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			writeSanitised(b, c)
		}
		return
	default:
		// Comments, doctypes and anything else contribute nothing.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			writeSanitised(b, c)
		}
	}
}

// PlainParagraphs renders a fragment as plain-text blocks, one per paragraph or list item.
//
// The report embeds SanitisedHTML because a downloaded file benefits from real markup. The console
// takes this instead, so the React side never needs dangerouslySetInnerHTML at all. That is a
// deliberate asymmetry rather than an inconsistency: the catalogue is trusted and sanitised, so
// rendering its markup would be defensible — but "defensible" is a weaker property than "structurally
// impossible", and an XSS in the operator's own console is the one bug this tool least gets to have.
// The cost is losing inline emphasis and list markers, which is a fair trade for the paragraph breaks
// that carry the actual readability.
func PlainParagraphs(fragment string) []string {
	if strings.TrimSpace(fragment) == "" {
		return nil
	}
	nodes, err := xhtml.ParseFragment(strings.NewReader(fragment), &xhtml.Node{
		Type: xhtml.ElementNode, Data: "body", DataAtom: atom.Body,
	})
	if err != nil {
		return []string{strings.TrimSpace(fragment)}
	}
	var out []string
	for _, n := range nodes {
		collectBlocks(n, &out)
	}
	// A fragment with no block elements at all is still one paragraph of prose, not nothing.
	if len(out) == 0 {
		var b strings.Builder
		for _, n := range nodes {
			collectText(n, &b)
		}
		if t := squashSpace(b.String()); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// blockElements start a new rendered block. Kept narrow on purpose: these are the ones the catalogue
// actually uses to separate thoughts.
var blockElements = map[atom.Atom]bool{atom.P: true, atom.Li: true, atom.H4: true, atom.H5: true, atom.H6: true, atom.Pre: true}

func collectBlocks(n *xhtml.Node, out *[]string) {
	if n.Type == xhtml.ElementNode && blockElements[n.DataAtom] {
		var b strings.Builder
		collectText(n, &b)
		if t := squashSpace(b.String()); t != "" {
			*out = append(*out, t)
		}
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectBlocks(c, out)
	}
}

func collectText(n *xhtml.Node, b *strings.Builder) {
	if n.Type == xhtml.TextNode {
		b.WriteString(n.Data)
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectText(c, b)
	}
}

// squashSpace collapses the source's hard-wrapped whitespace so a paragraph is one line of prose.
func squashSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
