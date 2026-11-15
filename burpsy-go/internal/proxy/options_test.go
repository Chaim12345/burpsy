package proxy

import (
	"bytes"
	"errors"

	"fmt"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// htmlResponse builds a plausible HTML response around a body.
func htmlResponse(body string) []byte {
	return []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"\r\n" + body)
}

// bodyOf splits a response and returns the body, so an assertion reads about the
// body rather than about the whole message.
func bodyOf(t *testing.T, raw []byte) string {
	t.Helper()
	_, body, _, ok := httputil.SplitHeadBody(raw)
	if !ok {
		t.Fatalf("response has no header/body separator: %q", raw)
	}
	return string(body)
}

func optionsWith(t *testing.T, keys ...OptionKey) *Options {
	t.Helper()
	o := NewOptions()
	for _, key := range keys {
		if err := o.Set(key, true); err != nil {
			t.Fatalf("Set(%q): %v", key, err)
		}
	}
	return o
}

// Each rule, over a body shaped like the markup it exists for. One test per rule so a
// failure names the rule rather than "response modification is broken".
func Test_each_response_rule_rewrites_the_markup_it_names(t *testing.T) {
	cases := []struct {
		name    string
		key     OptionKey
		in      string
		want    string
		absent  []string
		present []string
	}{
		{
			name: "unhide hidden form fields",
			key:  OptUnhideHiddenFormFields,
			in:   `<form><input type="hidden" name="csrf" value="abc"><input type=hidden name=b><input type='hidden' name=c><input type="text" name="q"></form>`,
			want: `<form><input type="text" name="csrf" value="abc"><input type=text name=b><input type='text' name=c><input type="text" name="q"></form>`,
		},
		{
			name:   "remove object tags",
			key:    OptRemoveObjectTags,
			in:     `<p>before</p><object data="x.swf"><param name="a" value="b"></object><object data="y" /><p>after</p>`,
			want:   `<p>before</p><p>after</p>`,
			absent: []string{"<object", "x.swf", "<param"},
		},
		{
			name:   "remove javascript form validation",
			key:    OptRemoveJSFormValidation,
			in:     `<form onsubmit="return validate(this)" onreset='clear()' action="/pay" onclick="log()">`,
			want:   `<form action="/pay" onclick="log()">`,
			absent: []string{"onsubmit", "onreset", "validate"},
			// onclick survives: this rule is about the form's validation hooks, and a
			// rule that removed every handler would be remove_all_javascript.
			present: []string{"onclick"},
		},
		{
			name:   "remove all javascript",
			key:    OptRemoveAllJavaScript,
			in:     `<head><script src="/a.js"></script><script>alert(1)</script></head><body onload="boot()"><a href="javascript:steal()">x</a><a href="/safe">y</a></body>`,
			want:   `<head></head><body><a href="#">x</a><a href="/safe">y</a></body>`,
			absent: []string{"<script", "alert(1)", "onload", "javascript:", "steal"},
		},
		{
			name:   "convert https links to http",
			key:    OptConvertHTTPSLinks,
			in:     `<a href="https://a.test/x">a</a><img src='https://b.test/i.png'><form action=https://c.test/p>`,
			want:   `<a href="http://a.test/x">a</a><img src='http://b.test/i.png'><form action=http://c.test/p>`,
			absent: []string{"https://"},
		},
		{
			name: "enable disabled form fields",
			key:  OptEnableDisabledFormFields,
			in: `<form>` +
				`<input type="text" name="a" disabled>` +
				`<input type="text" name="b" disabled="disabled">` +
				`<input type="text" name="c" disabled='disabled'>` +
				`<textarea name="d" disabled>text</textarea>` +
				`<select name="e" disabled><option value="1" disabled>one</option></select>` +
				`<button type="submit" disabled = "disabled">go</button>` +
				`<fieldset disabled><input name="f"></fieldset>` +
				`</form>` +
				// Not form controls, and not the attribute: both must survive.
				`<p data-x="disabled">keep</p><input name="g" xdisabled>`,
			want: `<form>` +
				`<input type="text" name="a">` +
				`<input type="text" name="b">` +
				`<input type="text" name="c">` +
				`<textarea name="d">text</textarea>` +
				`<select name="e"><option value="1">one</option></select>` +
				`<button type="submit">go</button>` +
				`<fieldset><input name="f"></fieldset>` +
				`</form>` +
				`<p data-x="disabled">keep</p><input name="g" xdisabled>`,
		},
		{
			name: "remove input field length limits",
			key:  OptRemoveInputFieldLengthLimits,
			in: `<form>` +
				`<input type="text" name="a" maxlength="5">` +
				`<input type="text" name="b" maxlength='10'>` +
				`<input type="text" name="c" maxlength = 15>` +
				`<textarea name="d" maxlength="20">text</textarea>` +
				// maxlength is defined on input and textarea only: a select's must
				// survive, and so must a name that merely contains the word.
				`<select name="e" maxlength="3"></select><input name="f" xmaxlength="9">`,
			want: `<form>` +
				`<input type="text" name="a">` +
				`<input type="text" name="b">` +
				`<input type="text" name="c">` +
				`<textarea name="d">text</textarea>` +
				`<select name="e" maxlength="3"></select><input name="f" xmaxlength="9">`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := optionsWith(t, tc.key)
			out := o.ApplyResponse(htmlResponse(tc.in))
			got := bodyOf(t, out)
			if got != tc.want {
				t.Errorf("body =\n  %q\nwant\n  %q", got, tc.want)
			}
			for _, needle := range tc.absent {
				if strings.Contains(got, needle) {
					t.Errorf("body still contains %q: %q", needle, got)
				}
			}
			for _, needle := range tc.present {
				if !strings.Contains(got, needle) {
					t.Errorf("body lost %q, which this rule does not touch: %q", needle, got)
				}
			}
			// Content-Length must describe the body that is actually there, or the
			// client hangs waiting for bytes the rule deleted.
			if want := "Content-Length: " + strconv.Itoa(len(got)); !strings.Contains(string(out), want) {
				t.Errorf("%q missing from the rewritten head: %q", want, out)
			}
			if c := o.Counters(); c.Modified != 1 || c.Considered != 1 {
				t.Errorf("counters = %+v, want one considered and one modified", c)
			}
		})
	}
}

// Every rule off means every byte untouched, and no counter moves. This is the
// default state, so it is the one that must cost nothing.
func Test_no_rule_enabled_leaves_the_response_untouched_and_uncounted(t *testing.T) {
	raw := htmlResponse(`<script>alert(1)</script><input type="hidden" name="x">`)
	o := NewOptions()
	out := o.ApplyResponse(raw)
	if &out[0] != &raw[0] {
		t.Error("ApplyResponse copied a response it had no rule for")
	}
	if c := o.Counters(); c != (Counters{}) {
		t.Errorf("counters = %+v, want all zero: a response no rule was enabled for was never a candidate", c)
	}
}

// The three refusals, each counted apart from the others. This is the honest-counting
// requirement in the small: an operator who ticks a box and sees nothing change must
// be able to read which of these happened.
func Test_a_response_the_rules_may_not_touch_is_skipped_for_a_named_reason(t *testing.T) {
	t.Run("a compressed body is left alone", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n" +
			"Content-Length: 24\r\n\r\n<script>alert(1)</script>")
		out := o.ApplyResponse(raw)
		if string(out) != string(raw) {
			t.Error("a gzip body was rewritten as if it were text")
		}
		if c := o.Counters(); c.SkippedCompressed != 1 || c.Modified != 0 {
			t.Errorf("counters = %+v, want one skipped_compressed", c)
		}
	})

	t.Run("a non-HTML body is left alone", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		body := `{"markup":"<script>alert(1)</script>"}`
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		out := o.ApplyResponse(raw)
		if string(out) != string(raw) {
			t.Errorf("a JSON body was rewritten: %q", out)
		}
		if c := o.Counters(); c.SkippedNotHTML != 1 {
			t.Errorf("counters = %+v, want one skipped_not_html", c)
		}
	})

	t.Run("a message with no header/body separator is left alone", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html")
		if string(o.ApplyResponse(raw)) != string(raw) {
			t.Error("a truncated head was rewritten")
		}
		if c := o.Counters(); c.SkippedUnframed != 1 {
			t.Errorf("counters = %+v, want one skipped_unframed", c)
		}
	})

	t.Run("identity encoding is not a reason to skip", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		body := `<script>alert(1)</script>ok`
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: identity\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		out := o.ApplyResponse(raw)
		if got := bodyOf(t, out); got != "ok" {
			t.Errorf("body = %q, want %q", got, "ok")
		}
	})
}

// A response the rules were allowed to rewrite and found nothing in is `unchanged`,
// not `modified` and not skipped. Three states, three counters.
func Test_a_response_with_nothing_to_rewrite_is_counted_unchanged(t *testing.T) {
	o := optionsWith(t, OptRemoveAllJavaScript)
	raw := htmlResponse(`<p>no script here</p>`)
	out := o.ApplyResponse(raw)
	if string(out) != string(raw) {
		t.Errorf("bytes changed with no rule match: %q", out)
	}
	c := o.Counters()
	if c.Considered != 1 || c.Unchanged != 1 || c.Modified != 0 {
		t.Errorf("counters = %+v, want one considered and one unchanged", c)
	}
}

// Chunk framing is collapsed only when a rule actually fired, and the resulting
// message is framed by Content-Length with no Transfer-Encoding left behind.
func Test_a_chunked_html_body_is_rewritten_and_reframed(t *testing.T) {
	chunked := func(parts ...string) []byte {
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
		for _, part := range parts {
			fmt.Fprintf(&b, "%x\r\n%s\r\n", len(part), part)
		}
		b.WriteString("0\r\n\r\n")
		return []byte(b.String())
	}

	t.Run("a rule that fires reframes the message", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		// Deliberately split so the script element spans two chunks: this is the case
		// a rule applied to the framed bytes could never match.
		out := o.ApplyResponse(chunked("<p>a</p><scr", "ipt>alert(1)</script><p>b</p>"))
		if got := bodyOf(t, out); got != "<p>a</p><p>b</p>" {
			t.Errorf("body = %q, want %q", got, "<p>a</p><p>b</p>")
		}
		head := string(out[:strings.Index(string(out), "\r\n\r\n")])
		if strings.Contains(strings.ToLower(head), "transfer-encoding") {
			t.Errorf("Transfer-Encoding survived a body that is no longer chunked: %q", head)
		}
		if !strings.Contains(head, "Content-Length: 16") {
			t.Errorf("head does not frame the new body: %q", head)
		}
		if c := o.Counters(); c.Dechunked != 1 || c.Modified != 1 {
			t.Errorf("counters = %+v, want one dechunked and one modified", c)
		}
	})

	t.Run("a rule that finds nothing leaves the framing alone", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		raw := chunked("<p>a</p>", "<p>b</p>")
		if string(o.ApplyResponse(raw)) != string(raw) {
			t.Error("a response no rule touched was re-framed anyway")
		}
		if c := o.Counters(); c.Dechunked != 0 || c.Unchanged != 1 {
			t.Errorf("counters = %+v, want no dechunk and one unchanged", c)
		}
	})

	t.Run("unparseable chunk framing is refused rather than guessed at", func(t *testing.T) {
		o := optionsWith(t, OptRemoveAllJavaScript)
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"ff\r\n<script>alert(1)</script>\r\n0\r\n\r\n") // declares 255 bytes, sends 25
		if string(o.ApplyResponse(raw)) != string(raw) {
			t.Error("a body whose chunk sizes do not add up was rewritten")
		}
		if c := o.Counters(); c.SkippedUnframed != 1 {
			t.Errorf("counters = %+v, want one skipped_unframed", c)
		}
	})
}

// remove_secure_flag_from_cookies is a head rule, and its tests are head-shaped:
// what it must change is the Set-Cookie header, and what it must not change is
// everything else — the body, the other headers, a cookie flag it did not name.
func Test_remove_secure_flag_from_cookies_rewrites_the_head_and_nothing_else(t *testing.T) {
	t.Run("the Secure attribute is removed and the rest of the cookie survives", func(t *testing.T) {
		raw := htmlResponse(`<html></html>`)
		raw = []byte(strings.Replace(string(raw), "Content-Type: text/html; charset=utf-8\r\n",
			"Content-Type: text/html; charset=utf-8\r\nSet-Cookie: session=abc123; Secure; Path=/\r\n", 1))
		o := optionsWith(t, OptRemoveSecureFlagFromCookies)
		out := o.ApplyResponse(raw)

		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(strings.ToLower(head), "secure") {
			t.Errorf("Secure survived the strip: %q", head)
		}
		if !strings.Contains(head, "Set-Cookie: session=abc123; Path=/") {
			t.Errorf("the rest of the cookie did not survive: %q", head)
		}
		if got := bodyOf(t, out); got != `<html></html>` {
			t.Errorf("the body was touched by a head rule: %q", got)
		}
		if c := o.Counters(); c.Considered != 1 || c.Modified != 1 || c.Unchanged != 0 {
			t.Errorf("counters = %+v, want one considered and one modified", c)
		}
	})

	t.Run("a non-HTML body does not gate it", func(t *testing.T) {
		body := `{"session":"abc"}`
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
			"Set-Cookie: sid=xyz; Path=/; Secure; HttpOnly\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		o := optionsWith(t, OptRemoveSecureFlagFromCookies)
		out := o.ApplyResponse(raw)

		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(head, "Secure") {
			t.Errorf("Secure survived on a JSON response: %q", head)
		}
		if c := o.Counters(); c.SkippedNotHTML != 0 || c.Modified != 1 {
			t.Errorf("counters = %+v: a JSON endpoint can set cookies, so this is a modification, not a skip", c)
		}
	})

	t.Run("header and attribute casing do not matter", func(t *testing.T) {
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
			"set-cookie: a=1; SECURE\r\n" +
			"SET-COOKIE: b=2; secure\r\n" +
			"Content-Length: 0\r\n\r\n")
		o := optionsWith(t, OptRemoveSecureFlagFromCookies)
		out := o.ApplyResponse(raw)
		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(strings.ToLower(head), "secure") {
			t.Errorf("a differently cased Secure survived: %q", head)
		}
		if !strings.Contains(head, "set-cookie: a=1") || !strings.Contains(head, "SET-COOKIE: b=2") {
			t.Errorf("the headers were not preserved as sent: %q", head)
		}
	})

	t.Run("only the exact attribute is removed", func(t *testing.T) {
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
			"Set-Cookie: a=1; SecureX; Path=/\r\n" +
			"Set-Cookie: b=insecure-value; HttpOnly\r\n" +
			"X-Note: Secure\r\n" +
			"Content-Length: 0\r\n\r\n")
		o := optionsWith(t, OptRemoveSecureFlagFromCookies)
		out := o.ApplyResponse(raw)
		if string(out) != string(raw) {
			t.Errorf("a response with no exact Secure attribute was changed: %q", out)
		}
		if c := o.Counters(); c.Unchanged != 1 || c.Modified != 0 {
			t.Errorf("counters = %+v, want one unchanged", c)
		}
	})

	t.Run("a compressed response's head is still reachable", func(t *testing.T) {
		packed := gzipBytes(t, `<html></html>`)
		raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n"+
			"Set-Cookie: session=abc; Secure\r\n"+
			"Content-Length: "+strconv.Itoa(len(packed))+"\r\n\r\n"), packed...)
		o := optionsWith(t, OptRemoveSecureFlagFromCookies)
		out := o.ApplyResponse(raw)

		sep := bytes.Index(out, []byte("\r\n\r\n"))
		head := string(out[:sep])
		if strings.Contains(head, "Secure") {
			t.Errorf("Secure survived on a compressed response: %q", head)
		}
		if !bytes.Equal(out[sep+4:], packed) {
			t.Error("the gzip body was touched by a head rule")
		}
		// Both facts are true and both are counted: the head rule changed the
		// message, and the body rules never got to look at the body.
		if c := o.Counters(); c.SkippedCompressed != 1 || c.Modified != 1 {
			t.Errorf("counters = %+v, want one skipped_compressed and one modified", c)
		}
	})

	t.Run("it composes with a body rule on a non-HTML body", func(t *testing.T) {
		body := `{"session":"abc"}`
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
			"Set-Cookie: sid=xyz; Secure\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		o := optionsWith(t, OptRemoveSecureFlagFromCookies, OptRemoveAllJavaScript)
		out := o.ApplyResponse(raw)

		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(head, "Secure") {
			t.Errorf("the head change did not survive the body skip: %q", head)
		}
		if c := o.Counters(); c.SkippedNotHTML != 1 || c.Modified != 1 {
			t.Errorf("counters = %+v, want one skipped_not_html and one modified", c)
		}
	})

	// The composition the non-HTML case above does NOT cover, and the one that was broken: the
	// body rules ran, found nothing, and the head change was thrown away on the way out. Ticking
	// "Remove secure flag from cookies" alongside any body rule must not silently switch it off
	// for HTML responses the body rule had no work in.
	t.Run("the head change survives an HTML body the rules found nothing to rewrite in", func(t *testing.T) {
		raw := htmlResponse(`<html><body>nothing to rewrite here</body></html>`)
		raw = []byte(strings.Replace(string(raw), "Content-Type: text/html; charset=utf-8\r\n",
			"Content-Type: text/html; charset=utf-8\r\nSet-Cookie: session=abc; Secure; Path=/\r\n", 1))
		o := optionsWith(t, OptRemoveSecureFlagFromCookies, OptRemoveAllJavaScript)
		out := o.ApplyResponse(raw)

		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(strings.ToLower(head), "secure") {
			t.Errorf("Secure survived an HTML response the body rule did not change: %q", head)
		}
		if got := bodyOf(t, out); got != `<html><body>nothing to rewrite here</body></html>` {
			t.Errorf("the body was touched by a head rule: %q", got)
		}
		// The message really did change, so it is a modification. Counting it unchanged would
		// report the option as having had nothing to do, which is the counter lying about the
		// feature rather than about the bytes.
		if c := o.Counters(); c.Modified != 1 || c.Unchanged != 0 {
			t.Errorf("counters = %+v, want one modified and no unchanged", c)
		}
	})

	// The other skip that used to drop it: a body whose chunk sizes do not add up. The head is
	// still the head, and the cookie flag is still in it.
	t.Run("the head change survives unparseable chunk framing", func(t *testing.T) {
		raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
			"Set-Cookie: session=abc; Secure\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"ff\r\n<script>alert(1)</script>\r\n0\r\n\r\n") // declares 255 bytes, sends 25
		o := optionsWith(t, OptRemoveSecureFlagFromCookies, OptRemoveAllJavaScript)
		out := o.ApplyResponse(raw)

		head := string(out[:bytes.Index(out, []byte("\r\n\r\n"))])
		if strings.Contains(strings.ToLower(head), "secure") {
			t.Errorf("Secure survived a response whose body rules skipped: %q", head)
		}
		if c := o.Counters(); c.SkippedUnframed != 1 || c.Modified != 1 {
			t.Errorf("counters = %+v, want one skipped_unframed and one modified", c)
		}
	})
}

func Test_strip_accept_encoding_removes_the_header_and_counts_only_real_strips(t *testing.T) {
	o := optionsWith(t, OptStripAcceptEncoding)

	withHeader := []byte("GET / HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip, br\r\nAccept: */*\r\n\r\n")
	out := o.ApplyRequest(withHeader)
	if strings.Contains(strings.ToLower(string(out)), "accept-encoding") {
		t.Errorf("Accept-Encoding survived: %q", out)
	}
	if !strings.Contains(string(out), "Host: a.test") || !strings.Contains(string(out), "Accept: */*") {
		t.Errorf("the strip took other headers with it: %q", out)
	}
	if !strings.HasSuffix(string(out), "\r\n\r\n") {
		t.Errorf("the head terminator was lost: %q", out)
	}

	// A request that never offered an encoding is not evidence the option is working,
	// so it must not be counted as a strip.
	without := []byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	if string(o.ApplyRequest(without)) != string(without) {
		t.Error("a request with no Accept-Encoding was rewritten")
	}
	if c := o.Counters(); c.AcceptEncodingStripped != 1 {
		t.Errorf("accept_encoding_stripped = %d, want 1", c.AcceptEncodingStripped)
	}

	// A body must survive the header surgery byte for byte.
	withBody := []byte("POST /p HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello")
	if got := string(o.ApplyRequest(withBody)); !strings.HasSuffix(got, "\r\n\r\nhello") {
		t.Errorf("body did not survive: %q", got)
	}
}

// The strip is the one option whose engine default is on: NewProxyConfig seeds it
// so a fresh proxy keeps captures readable, and every other option stays off until
// an operator moves it. Pin both halves — the seed and the off state — because a
// silent default drift would either leak compressed frames into history (seed lost)
// or lock testers out of origins that require the extension (seed forced).
func Test_the_websocket_handshake_strip_defaults_on_and_round_trips(t *testing.T) {
	c := NewProxyConfig(core.NewTrafficStore())
	if !c.Options().Get(OptStripWsExtensions) {
		t.Fatal("a fresh proxy does not strip Sec-WebSocket-Extensions; history would record permessage-deflate frames as though they were plaintext")
	}
	if err := c.Options().Set(OptStripWsExtensions, false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if c.Options().Get(OptStripWsExtensions) {
		t.Fatal("Set(false) did not take")
	}
	// The builder writes the same set, not a second copy — a second copy would let
	// the panel and the handshake disagree about what stripping is on.
	c.WithStripWsExtensions(true)
	if !c.Options().Get(OptStripWsExtensions) {
		t.Fatal("WithStripWsExtensions wrote somewhere other than the live option set")
	}
}

func Test_an_unknown_option_key_is_refused_by_name(t *testing.T) {
	o := NewOptions()
	err := o.Set(OptionKey("remove_all_javescript"), true)
	if !errors.Is(err, ErrUnknownOption) {
		t.Fatalf("Set of an unknown key returned %v, want ErrUnknownOption", err)
	}
	if !strings.Contains(err.Error(), "remove_all_javescript") {
		t.Errorf("the error does not name the key: %v", err)
	}
	// And the snapshot still describes exactly the real options, so a typo cannot
	// leave a phantom key the UI would render as a control.
	snap := o.Snapshot()
	if len(snap) != len(OptionKeys) {
		t.Errorf("snapshot has %d keys, want %d", len(snap), len(OptionKeys))
	}
	for _, key := range OptionKeys {
		if _, ok := snap[string(key)]; !ok {
			t.Errorf("snapshot is missing %q", key)
		}
	}
}

// A nil option set is a supported state: the tests in this package build a Server
// directly, and so does anything that has no use for these rules.
func Test_a_nil_option_set_reads_as_every_rule_off(t *testing.T) {
	var o *Options
	raw := htmlResponse(`<script>alert(1)</script>`)
	if string(o.ApplyResponse(raw)) != string(raw) {
		t.Error("a nil option set rewrote a response")
	}
	if string(o.ApplyRequest(raw)) != string(raw) {
		t.Error("a nil option set rewrote a request")
	}
	o.NoteRelayedHTTP2()
	if c := o.Counters(); c != (Counters{}) {
		t.Errorf("counters = %+v, want all zero", c)
	}
	for key, on := range o.Snapshot() {
		if on {
			t.Errorf("%q reads as on from a nil option set", key)
		}
	}
}

// ---- through the real proxy ----------------------------------------------------
//
// The unit tests above prove the rewrites. This one proves they are wired into the
// response path in the slot that keeps the package's invariant: the bytes the client
// received and the bytes history recorded are the same bytes, and both are the
// rewritten ones.

func Test_response_rules_rewrite_real_traffic_and_history_agrees(t *testing.T) {
	const origin = `<html><body><input type="hidden" name="csrf" value="s3cret">` +
		`<script>document.forms[0].submit()</script>` +
		`<a href="https://cdn.test/x">cdn</a></body></html>`

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back what the proxy actually sent us, so the request-direction option
		// is observable from the response.
		w.Header().Set("X-Saw-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, origin)
	}))
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	tport, _ := strconv.Atoi(tportStr)

	options := optionsWith(t,
		OptUnhideHiddenFormFields,
		OptRemoveAllJavaScript,
		OptConvertHTTPSLinks,
		OptStripAcceptEncoding,
	)

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithOptions(options))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		DisableCompression: true, // so the offer below is the one the test set, not Go's
	}}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/", thost, tport), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// The client got the rewritten page. Content-Length has to be right for this read
	// to have terminated at all, which is half the point of asserting on the body.
	got := string(body)
	if strings.Contains(got, `type="hidden"`) {
		t.Errorf("the hidden field reached the browser hidden: %q", got)
	}
	if !strings.Contains(got, `type="text"`) {
		t.Errorf("the hidden field was not unhidden: %q", got)
	}
	if strings.Contains(got, "<script") {
		t.Errorf("script survived to the browser: %q", got)
	}
	if !strings.Contains(got, `href="http://cdn.test/x"`) {
		t.Errorf("the https link was not downgraded: %q", got)
	}

	// The origin saw no Accept-Encoding, which is what let it answer in plaintext and
	// therefore what let the rules above fire at all.
	if saw := resp.Header.Get("X-Saw-Accept-Encoding"); saw != "" {
		t.Errorf("the origin saw Accept-Encoding %q; the strip did not reach the wire", saw)
	}

	// And history holds those same bytes, in both directions. This is the assertion
	// that would fail if the rules ran after the record or after the write.
	ex := awaitExchange(t, store)
	storedResp, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("stored response: %v", err)
	}
	recorded := string(storedResp.Raw())
	if !strings.HasSuffix(recorded, got) {
		t.Errorf("history's response body is not the bytes the client received.\nrecorded: %q\nclient:   %q", recorded, got)
	}
	storedReq, err := store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		t.Fatalf("stored request: %v", err)
	}
	if strings.Contains(strings.ToLower(string(storedReq.Raw())), "accept-encoding") {
		t.Errorf("history shows an Accept-Encoding the origin never received: %q", storedReq.Raw())
	}

	c := options.Counters()
	if c.Modified != 1 || c.AcceptEncodingStripped != 1 {
		t.Errorf("counters = %+v, want one modified response and one stripped request", c)
	}
}

// Burp's "Support invisible proxying": a client that is not proxy-aware sends
// origin-form with the authority in the Host header. The headers it sent must reach
// the origin — before this, the Host lookup consumed them off the reader and
// readFullRequest returned a request line with nothing after it.
func Test_invisible_proxying_forwards_the_headers_the_client_sent(t *testing.T) {
	saw := make(chan http.Header, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw <- r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer target.Close()

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	// Origin-form request line and an authority only in Host — exactly what a browser
	// sends when DNS points the origin's name at this listener.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	authority := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\nHost: %s\r\nX-Marker: kept\r\nAccept: */*\r\n\r\n", authority)

	select {
	case headers := <-saw:
		if headers.Get("X-Marker") != "kept" {
			t.Errorf("the origin received %v; the client's headers were dropped on the way through", headers)
		}
		if headers.Get("Accept") != "*/*" {
			t.Errorf("Accept did not survive: %v", headers)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the origin was never reached")
	}

	ex := awaitExchange(t, store)
	if ex.Path != "/probe" {
		t.Errorf("recorded path = %q, want /probe", ex.Path)
	}
	stored, err := store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		t.Fatalf("stored request: %v", err)
	}
	if !strings.Contains(string(stored.Raw()), "X-Marker: kept") {
		t.Errorf("history recorded a request without the client's headers: %q", stored.Raw())
	}
}

// burpsy-react-ui-6858 fix round: the HTML check reads Content-Type with the strict shape the
// retired headerValue used, so a padded field name does not route a response into the markup
// rules.
func Test_isHTMLResponse_ignores_a_padded_content_type(t *testing.T) {
	if isHTMLResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type : text/html\r\n")) {
		t.Error("a Content-Type padded before its colon was read as HTML")
	}
	if !isHTMLResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n")) {
		t.Error("a plain Content-Type stopped reading as HTML")
	}
}

// The invisible-routing branch in proxy.go's serve loop reads Host as
// HeaderValueExact(requestHead(requestData), "Host") — this pins the strict shape of that exact
// read, so the branch cannot quietly go lenient (a padded Host line a strict parser ignores must
// not pick the origin; the live listener test binds the same contract end to end).
func Test_the_invisible_routing_host_read_keeps_the_strict_shape(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost : example.com\r\n\r\n")
	if h, _ := httputil.HeaderValueExact(requestHead(req), "Host"); h != "" {
		t.Errorf("a padded Host line read as %q", h)
	}
	req = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if h, _ := httputil.HeaderValueExact(requestHead(req), "Host"); h != "example.com" {
		t.Errorf("a plain Host line read as %q", h)
	}
}

// The panel hears about real movement and only real movement: a flipped flag and a moved
// counter announce, a no-op Set and a response no rule was enabled for stay silent - the
// difference between a live panel and one that refetches on every proxied response.
func TestOnChangeAnnouncesMovementAndStaysSilentOtherwise(t *testing.T) {
	o := NewOptions()
	calls := 0
	o.OnChange(func() { calls++ })

	// A no-op Set leaves the flag as it was: nothing moved, nothing announced.
	if err := o.Set(OptRemoveAllJavaScript, false); err != nil {
		t.Fatalf("no-op Set: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a no-op Set announced %d changes, want 0", calls)
	}

	// A real flip announces once.
	if err := o.Set(OptRemoveAllJavaScript, true); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if calls != 1 {
		t.Fatalf("a flag flip announced %d changes, want 1", calls)
	}

	// A response no untouched-rule path touches moves no counter and stays silent.
	o2 := NewOptions()
	calls2 := 0
	o2.OnChange(func() { calls2++ })
	raw := htmlResponse(`<p>plain</p>`)
	o2.ApplyResponse(raw)
	if calls2 != 0 {
		t.Fatalf("a response with no rule enabled announced %d changes, want 0", calls2)
	}

	// A response a rule rewrites moves counters, and the panel hears it.
	o3 := optionsWith(t, OptRemoveAllJavaScript)
	calls3 := 0
	o3.OnChange(func() { calls3++ })
	o3.ApplyResponse(htmlResponse(`<script>alert(1)</script><p>kept</p>`))
	if calls3 == 0 {
		t.Fatal("a rewritten response announced nothing")
	}
	if c := o3.Counters(); c.Modified == 0 {
		t.Fatal("a rewritten response moved no Modified counter - the test proves nothing")
	}
}
