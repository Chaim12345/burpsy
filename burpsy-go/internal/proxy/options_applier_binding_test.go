package proxy

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"strings"
	"testing"
)

// ---- every listed option must actually be applied ---------------------------------------
//
// `OptionKeys` is the vocabulary the API exposes: `KnownOption` validates against it,
// `Snapshot` reports it, and `PUT /api/proxy/options` accepts anything in it. Whether a key
// in that list does anything is a separate question, and until this file nothing asked it.
//
// BURP_PARITY_GAP_ANALYSIS.md §9.4 named the gap precisely: three tests bind the option
// *listing* and zero bind the *applier*. `Test_each_response_rule_rewrites_the_markup_it_names`
// proves each rule works, but it iterates a hand-written `cases` slice — so a seventh option
// added to `OptionKeys` would be settable through the API, do nothing at all, and leave every
// existing test green.
//
// That is not a hypothetical shape. It is exactly how the match/replace param targets hid:
// `targetsDir` listed them, `applyOne` could not apply them, and no test bound the two. The
// listing said yes and the engine said nothing.
//
// So this file derives its coverage from `OptionKeys` itself and uses **no second table of
// option names**. A hand-written map from key to expected behaviour would reintroduce the same
// drift one layer up — the thing the report calls "the same silent-drift bug wearing the
// pattern's clothes".

// everyRuleMarkup contains something for each response rule to bite on, plus nothing that
// depends on which rule is enabled. One input for all keys is what removes the need for a
// per-key table: the test asks "did enabling this key alone change anything?", and only an
// applied option can answer yes.
const everyRuleMarkup = `<html><body>` +
	`<form onsubmit="validate()" onreset="clear()">` +
	`<input type="hidden" name="csrf" value="abc">` +
	`</form>` +
	`<object data="plugin.swf"><param name="a" value="b"></object>` +
	`<script>tracker()</script>` +
	`<a href="https://cdn.example.test/app.js" onclick="go()">link</a>` +
	`</body></html>`

// requestWithEncoding is the request-direction equivalent: a request carrying the one header
// strip_accept_encoding exists to strip.
func requestWithEncoding() []byte {
	return []byte("GET /page HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"\r\n")
}

// gzipBytes compresses one string, for the two unpack fixtures below.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// gzippedHTMLResponse and gzippedRequest are the fixtures the two unpack options act on.
//
// They are separate inputs rather than replacements for the plain ones, because no single message can
// exercise every option: the five rewriting rules need a plaintext HTML body, and the unpack switches
// need a compressed one. Compressing the shared fixture would have made the rewriting rules skip
// unless unpacking were also on, which is exactly the "enabled alone" condition this test asserts.
func gzippedHTMLResponse(t *testing.T, body string) []byte {
	t.Helper()
	packed := gzipBytes(t, body)
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n"
	return append([]byte(head), packed...)
}

func gzippedRequest(t *testing.T, body string) []byte {
	t.Helper()
	packed := gzipBytes(t, body)
	head := "POST /page HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n"
	return append([]byte(head), packed...)
}

// The binding itself: enabling any single listed option, alone, must change *something* in
// one direction or the other.
//
// This is deliberately a weak assertion about *what* changes and a strong assertion about
// *whether* anything does. The per-rule tests already pin the exact markup each rule produces;
// what was missing was a statement that the set of options the API advertises and the set the
// engine acts on are the same set. A key that changes nothing in either direction is a switch
// the operator can turn on that does nothing — reported as enabled, doing nothing, which is
// this project's defining failure mode.
func Test_every_listed_option_changes_something_when_enabled_alone(t *testing.T) {
	if len(OptionKeys) == 0 {
		t.Fatal("OptionKeys is empty; there is nothing to bind")
	}
	for _, key := range OptionKeys {
		t.Run(string(key), func(t *testing.T) {
			o := optionsWith(t, key)

			resp := htmlResponse(everyRuleMarkup)
			respOut := o.ApplyResponse(resp)
			respChanged := !strings.EqualFold(string(respOut), string(resp))

			req := requestWithEncoding()
			reqOut := o.ApplyRequest(req)
			reqChanged := string(reqOut) != string(req)

			// The compressed pair, for the two unpack switches. Every option is offered every
			// fixture: an option that acts on the plain message and not the compressed one is still
			// bound, and asking "did anything change anywhere" keeps this test free of a per-key
			// table — which is the property the file header argues for at length.
			gzResp := gzippedHTMLResponse(t, everyRuleMarkup)
			gzRespOut := o.ApplyResponse(gzResp)
			respChanged = respChanged || string(gzRespOut) != string(gzResp)

			gzReq := gzippedRequest(t, everyRuleMarkup)
			gzReqOut := o.ApplyRequest(gzReq)
			reqChanged = reqChanged || string(gzReqOut) != string(gzReq)

			if !respChanged && !reqChanged {
				t.Fatalf("option %q is listed in OptionKeys but changed nothing in either "+
					"direction. Either it has no applier — in which case the API is advertising "+
					"a switch that does nothing — or everyRuleMarkup/requestWithEncoding no longer "+
					"contains anything for it to act on, in which case extend the fixture rather "+
					"than deleting this assertion.", key)
			}
			// A response-direction rule that fired must also have been counted, or the panel
			// will show a rewrite that the counters deny.
			if respChanged {
				if c := o.Counters(); c.Modified == 0 {
					t.Errorf("option %q rewrote the response but Modified is 0: %+v", key, c)
				}
			}
		})
	}
}

// The two sets the engine keeps internally must not drift from the advertised one either.
// `responseRules` is what `ApplyResponse` iterates; anything in it that is not public is a
// rule no operator can reach, and anything public that is in neither `responseRules` nor the
// request path is covered by the test above.
func Test_responseRules_is_a_subset_of_the_advertised_options(t *testing.T) {
	listed := make(map[OptionKey]bool, len(OptionKeys))
	for _, key := range OptionKeys {
		listed[key] = true
	}
	for _, key := range responseRules {
		if !listed[key] {
			t.Errorf("responseRules contains %q, which is not in OptionKeys — the engine applies "+
				"a rule the API will not let anyone enable", key)
		}
	}
	if len(responseRules) > len(OptionKeys) {
		t.Errorf("responseRules has %d entries and OptionKeys has %d", len(responseRules), len(OptionKeys))
	}
}

// KnownOption must agree with OptionKeys in both directions. It is the gate the PUT handler
// validates through, so a key it accepts that is not in the list would be settable and
// unreportable, and a listed key it rejects would be advertised and unsettable.
func Test_KnownOption_agrees_with_the_advertised_list(t *testing.T) {
	for _, key := range OptionKeys {
		if !KnownOption(key) {
			t.Errorf("OptionKeys advertises %q but KnownOption rejects it", key)
		}
	}
	for _, bogus := range []OptionKey{"", "remove_all_javascript ", "REMOVE_ALL_JAVASCRIPT", "not_an_option"} {
		if KnownOption(bogus) {
			t.Errorf("KnownOption accepted %q, which is not in OptionKeys", bogus)
		}
	}
}

// Every advertised option must be settable and must read back. Snapshot is what the panel
// renders, so an option that Set accepts but Snapshot omits is a switch the operator flips
// and then cannot see the state of.
func Test_every_listed_option_round_trips_through_Set_and_Snapshot(t *testing.T) {
	o := NewOptions()
	for _, key := range OptionKeys {
		if err := o.Set(key, true); err != nil {
			t.Fatalf("Set(%q): %v", key, err)
		}
	}
	snap := o.Snapshot()
	if len(snap) != len(OptionKeys) {
		t.Errorf("Snapshot has %d keys, OptionKeys has %d", len(snap), len(OptionKeys))
	}
	for _, key := range OptionKeys {
		on, present := snap[string(key)]
		if !present {
			t.Errorf("Snapshot omits %q", key)
			continue
		}
		if !on {
			t.Errorf("Snapshot reports %q as off after Set(true)", key)
		}
	}
}
