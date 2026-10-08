package crawler

import (
	"testing"
)

// The extraction surface (burpsy-react-ui-u967).
//
// Burp's link extraction reads more element/attribute pairs than the anchor set, and burpsy read
// five (a, area, iframe, frame, form). A page whose only action is a styled button carrying
// formaction contributed nothing at all, which is the shape a lot of modern markup takes.
//
// Equally important is what stays UNREAD: reading an inline `onclick` string as a URL requires a
// JavaScript parser this project cannot cite evidence for, and a guessed one would invent
// locations. The tests below pin both halves.

// formaction on a button is a navigation target. This is the case the bead names: without it a
// JS-driven app whose only action is a styled button contributes no links.
func TestAButtonFormactionIsALink(t *testing.T) {
	pages := map[string]string{}
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":              {`<html><body><button formaction="/submit-action">Go</button></body></html>`, "text/html"},
			"/submit-action": {`<html><body>done</body></html>`, "text/html"},
		}
	})
	_ = pages
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/submit-action") {
		t.Errorf("a button's formaction was not followed; a styled button is how a modern app "+
			"submits without a form element, so its target is a real location (fetched: %v)", fetchLog(rep))
	}
}

// input[formaction] is the same control on an input, and it overrides the enclosing form's action.
func TestAnInputFormactionIsALink(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":             {`<html><body><input type="submit" formaction="/input-action"></body></html>`, "text/html"},
			"/input-action": {`<html><body>done</body></html>`, "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/input-action") {
		t.Errorf("an input's formaction was not followed (fetched: %v)", fetchLog(rep))
	}
}

// math[href] — the MathML link element the HTML walk never visited.
func TestAMathHrefIsALink(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":      {`<html><body><math href="/maths"><mi>x</mi></math></body></html>`, "text/html"},
			"/maths": {`<html><body>done</body></html>`, "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/maths") {
		t.Errorf("math[href] was not followed (fetched: %v)", fetchLog(rep))
	}
}

// object[data] and embed[src] carry embedded documents, which are fetches the crawl never made.
func TestObjectDataAndEmbedSrcAreLinks(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":             {`<html><body><object data="/embedded.pdf"></object><embed src="/movie.swf"></body></html>`, "text/html"},
			"/embedded.pdf": {`%PDF-1.4`, "application/pdf"},
			"/movie.swf":    {`FWS`, "application/x-shockwave-flash"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/embedded.pdf") {
		t.Errorf("object[data] was not followed; the embedded document has its own locations "+
			"(fetched: %v)", fetchLog(rep))
	}
	if !fetchedAny(rep, "/movie.swf") {
		t.Errorf("embed[src] was not followed (fetched: %v)", fetchLog(rep))
	}
}

// The CONTROL half: an inline handler is NOT scraped for URLs. There is no citable evidence for
// Burp's inline-handler handling, and `onclick="doThing()"` is not a URL while
// `onclick="location='/x'"` is — reading some and not others on a heuristic this project cannot
// cite would invent locations. The rendered pass is what finds handler-delivered links.
func TestAnInlineHandlerIsNotScrapedForURLs(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/": {`<html><body>` +
				`<a href="#" onclick="location='/from-handler'">h</a>` +
				`<button onclick="window.open('/opened')">o</button>` +
				`</body></html>`, "text/html"},
			"/from-handler": {`<html><body>x</body></html>`, "text/html"},
			"/opened":       {`<html><body>x</body></html>`, "text/html"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if fetchedAny(rep, "/from-handler") || fetchedAny(rep, "/opened") {
		t.Errorf("a URL inside an inline handler was scraped and fetched; no citable rule says "+
			"which handler strings are URLs, and guessing invents requests the target never "+
			"published (fetched: %v)", fetchLog(rep))
	}
}

// Meta refresh is followed by default and not when the crawl is told not to (q0qr): Burp's
// http.redirections.understand_meta_refresh_tag, default true, which Config.NoMetaRefresh turns off.
func TestMetaRefreshIsFollowedUnlessTurnedOff(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":          {`<html><head><meta http-equiv="refresh" content="0; url=/refreshed"></head><body>x</body></html>`, "text/html"},
			"/refreshed": {`<html><body>x</body></html>`, "text/html"},
		}
	})
	if rep := run(t, newHarness().config(srv.URL+"/")); !fetchedAny(rep, "/refreshed") {
		t.Errorf("a meta refresh was not followed under Burp's default (fetched: %v)", fetchLog(rep))
	}
	cfg := newHarness().config(srv.URL + "/")
	cfg.NoMetaRefresh = true
	if rep := run(t, cfg); fetchedAny(rep, "/refreshed") {
		t.Errorf("understand_meta_refresh_tag false still followed the refresh (fetched: %v)", fetchLog(rep))
	}
}
