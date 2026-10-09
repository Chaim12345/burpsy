package session

import "testing"

// Burp's custom-parameter fields on a macro extraction (burpsy-react-ui-355h): the value a later
// step receives is prefix + extracted + suffix, percent-encoded only when the value is declared not
// to be URL-encoded already; an extraction with none of the fields is unchanged.
func TestCustomParameterPrefixSuffixAndEncoding(t *testing.T) {
	body := []byte(`<input name="csrf" value="a b&c">`)
	mk := func(prefix, suffix string, encoded *bool) *Extraction {
		ex, err := NewExtraction("csrf", "body", `value="([^"]*)"`, 1)
		if err != nil {
			t.Fatal(err)
		}
		ex.Prefix, ex.Suffix, ex.URLEncoded = prefix, suffix, encoded
		return ex
	}
	no, yes := false, true
	for name, c := range map[string]struct {
		ex   *Extraction
		want string
	}{
		"plain":                 {mk("", "", nil), "a b&c"},
		"prefix and suffix":     {mk("tok-", ";v=1", nil), "tok-a b&c;v=1"},
		"already encoded":       {mk("", "", &yes), "a b&c"},
		"raw, so it is encoded": {mk("x=", "", &no), "x%3Da+b%26c"},
	} {
		if got := c.ex.RunResult(nil, body); got.Value != c.want {
			t.Errorf("%s: value %q, want %q", name, got.Value, c.want)
		}
	}
}
