package apidoc

import "testing"

// ibhs: FuzzParse: the API document importer never panics on arbitrary bytes.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	f.Add([]byte("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n"))
	f.Add([]byte(`{"swagger":"2.0","paths":{}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://a/","headers":[]}}]}}`))
	f.Add([]byte("{"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
