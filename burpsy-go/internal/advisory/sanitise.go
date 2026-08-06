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
