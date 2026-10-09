package core

import (
	"reflect"
	"testing"
)

// RequestParameterNames (burpsy-react-ui-dnvi): the names a request carries, query and body.
func TestRequestParameterNamesReadsQueryAndBody(t *testing.T) {
	for name, c := range map[string]struct {
		raw  string
		want []string
	}{
		"query and urlencoded body, deduplicated": {
			"POST /a?x=1&y=2&x=3 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ny=1&z%5B%5D=2",
			[]string{"x", "y", "z[]"},
		},
		"multipart parts by form name, content with dashes": {
			"POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n\r\n" +
				"--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\na -- b --c\r\n" +
				"--XyZ\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\r\n\r\n--data--\r\n--XyZ--\r\n",
			[]string{"title", "upload"},
		},
		"no parameters": {"GET /static.css HTTP/1.1\r\nHost: h\r\n\r\n", nil},
		"an unparseable body names nothing": {
			"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1}", nil,
		},
	} {
		if got := RequestParameterNames([]byte(c.raw)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}
