package core

import "testing"

// burpsy-react-ui-7py5: a history row is an index entry with no request body, so the
// "Parameterized requests" filter counted the query string alone and dropped every body-only
// parameterized request — a JSON API POST, a multipart upload, an XML API call. Burp's
// SHOW_ONLY_PARAMETERIZED_REQUESTS accepts HttpParameterType.URL OR HttpParameterType.BODY
// (burp-re/out/clean/root/Zb2y.java:270-273,450-455).
//
// This is the projection those rows will read, computed once at capture where the bytes are already
// in hand — the same seam as Mime and RequestFingerprint.

func TestAQueryStringIsCountedAsBeforeSoNothingThatWorkedChanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{"two query parameters", "GET /search?q=alpha&page=2 HTTP/1.1\r\nHost: a.test\r\n\r\n", 2},
		{"one query parameter", "GET /x?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", 1},
		{"no query string", "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n", 0},
		{"empty query string", "GET /x? HTTP/1.1\r\nHost: a.test\r\n\r\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequestParameterCount([]byte(tc.raw)); got != tc.want {
				t.Errorf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

// The case the bead is about, in its three forms. Each of these was classified unparameterized by the
// path-only count, and each is exactly what an operator filters to parameterized traffic to find.
func TestABodyOnlyRequestIsParameterized(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{
			"a urlencoded form post",
			"POST /login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=hunter2",
			2,
		},
		{
			"a urlencoded body with no query string at all",
			"POST /api HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1",
			1,
		},
		{
			"a JSON API post",
			"POST /api/v1/login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}",
			1,
		},
		{
			"an XML API call",
			"POST /rpc HTTP/1.1\r\nHost: a.test\r\nContent-Type: text/xml\r\n\r\n<methodCall/>",
			1,
		},
		{
			"a body with no Content-Type at all",
			"POST /submit HTTP/1.1\r\nHost: a.test\r\n\r\nname=bob",
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequestParameterCount([]byte(tc.raw)); got != tc.want {
				t.Errorf("count = %d, want %d — a body-only request is parameterized traffic", got, tc.want)
			}
		})
	}
}

// A multipart upload is parameterized however large it is, and its parts are named parameters.
func TestAMultipartUploadIsCountedByItsNamedParts(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Type: multipart/form-data; boundary=BOUND\r\n\r\n" +
		"--BOUND\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nreport\r\n" +
		"--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\ndata\r\n" +
		"--BOUND--\r\n"
	if got := RequestParameterCount([]byte(raw)); got != 2 {
		t.Errorf("count = %d, want 2 (a title field and a named file part)", got)
	}

	// A file part counts because filename= names it, which is the case the fix would otherwise miss.
	single := "POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Type: multipart/form-data\r\n\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"big.bin\"\r\n\r\ndata\r\n--B--\r\n"
	if got := RequestParameterCount([]byte(single)); got != 1 {
		t.Errorf("count = %d, want 1 for a body that is only a named file part", got)
	}
}

// THE load-bearing decision: a body this function cannot parse is UNEXAMINED, not parameterless.
// Reporting zero would tell an operator a request has no parameters when nobody looked, and a filter
// that hides requests it could not read reports a clean answer about a request nobody read.
func TestAnUnreadableBodyIsCountedAsOneRatherThanZero(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	got := RequestParameterCount([]byte(raw))
	if got == 0 {
		t.Fatal("count = 0 for a body this function cannot parse; a filter that hides these reports " +
			"a clean answer about a request nobody examined")
	}
	if got != 1 {
		t.Errorf("count = %d, want 1: nobody knows how many parameters are in there, and a bigger "+
			"number would be a claim this function has no basis for", got)
	}
}

// And it is ONE only when the query string has not already answered the question. A request with a
// query string is parameterized whatever its body says.
func TestAQueryStringAnswersTheQuestionWhateverTheBodyIs(t *testing.T) {
	raw := "POST /api?trace=1 HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	if got := RequestParameterCount([]byte(raw)); got != 1 {
		t.Errorf("count = %d, want 1: the query parameter already answers it and the unreadable body "+
			"must not add to it", got)
	}
}

// A form body AND a query string report the total, which is what "has parameters" means.
func TestAQueryStringAndAFormBodyReportTheTotal(t *testing.T) {
	raw := "POST /api?format=json HTTP/1.1\r\nHost: a.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n\r\na=1&b=2"
	if got := RequestParameterCount([]byte(raw)); got != 3 {
		t.Errorf("count = %d, want 3 (one query parameter and two form fields)", got)
	}
}

// The media type is read past its parameters, because "application/x-www-form-urlencoded;
// charset=utf-8" is how a real header arrives and comparing the whole value would miss every one.
func TestTheMediaTypeIsReadPastItsParameters(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: a.test\r\n" +
		"Content-Type: Application/X-WWW-Form-Urlencoded; charset=UTF-8\r\n\r\na=1&b=2&c=3"
	if got := RequestParameterCount([]byte(raw)); got != 3 {
		t.Errorf("count = %d, want 3; the media type is case-insensitive and its parameters are not "+
			"part of the name", got)
	}
}

// A bare flag with no value is a parameter — it is a flag, and hiding it would hide a request whose
// behaviour the operator is trying to explain. An empty segment between separators is not, because
// it names nothing.
func TestABareFlagCountsAndAnEmptySegmentDoesNot(t *testing.T) {
	if got := RequestParameterCount([]byte("GET /x?debug HTTP/1.1\r\nHost: a.test\r\n\r\n")); got != 1 {
		t.Errorf("a bare ?debug counted %d, want 1", got)
	}
	if got := RequestParameterCount([]byte("GET /x?a=1&&b=2& HTTP/1.1\r\nHost: a.test\r\n\r\n")); got != 2 {
		t.Errorf("empty segments counted %d, want 2", got)
	}
}

// An absolute request-target, which a proxy-style client sends, carries its query after the origin.
func TestAnAbsoluteRequestTargetIsCounted(t *testing.T) {
	raw := "GET http://a.test/search?q=alpha&page=2 HTTP/1.1\r\nHost: a.test\r\n\r\n"
	if got := RequestParameterCount([]byte(raw)); got != 2 {
		t.Errorf("count = %d, want 2 for an absolute-form request target", got)
	}
}

// A message with no body and no query string is zero, and that is a real answer: there is nothing
// there to be uncertain about. The unexamined rule must not turn "certainly nothing" into "maybe one".
func TestARequestWithNeitherABodyNorAQueryStringIsZero(t *testing.T) {
	if got := RequestParameterCount([]byte("GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n")); got != 0 {
		t.Errorf("count = %d, want 0: nothing was there to be uncertain about", got)
	}
	if got := RequestParameterCount(nil); got != 0 {
		t.Errorf("count for no message = %d, want 0", got)
	}
	if got := RequestParameterCount([]byte{}); got != 0 {
		t.Errorf("count for an empty message = %d, want 0", got)
	}
}

// Bare LF framing is what a client that does not use CRLF sends, and a count that read a CRLF-only
// message as having no body would be wrong about every such request.
func TestBareLineFeedFramingIsRead(t *testing.T) {
	raw := "POST /login HTTP/1.1\nHost: a.test\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=x"
	if got := RequestParameterCount([]byte(raw)); got != 2 {
		t.Errorf("count = %d, want 2 for bare-LF framing", got)
	}
}

// A message with no header terminator is a fragment — a CONNECT tunnel, a malformed capture. It is
// counted from what is there rather than reported as nothing, because a fragment is not a message
// with no parameters.
func TestAFragmentWithNoHeaderTerminatorIsCountedFromWhatIsThere(t *testing.T) {
	if got := RequestParameterCount([]byte("GET /x?a=1 HTTP/1.1\r\nHost: a.test\r\n")); got != 1 {
		t.Errorf("count = %d, want 1; a fragment still carries the query string it shows", got)
	}
}
