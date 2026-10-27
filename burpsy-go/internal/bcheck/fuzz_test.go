package bcheck

import "testing"

// ibhs: FuzzParse: the bcheck definition parser never panics on arbitrary source.
func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("metadata:\n  language: v2-beta\n  name: x\n")
	f.Add("metadata:\n  language: v2-beta\n  name: x\n  description: d\n  author: a\n  tags: a, b\n\ndefine:\n  a = {base.request.url}\n\nrun for each:\n  p = \"a\", \"b\"\n\ngiven request then\n  send request called check:\n    method: \"GET\"\n")
	f.Add("{{{{")
	f.Add("a:\n\tb: \"unterminated")
	f.Fuzz(func(t *testing.T, src string) {
		_, _ = Parse(src)
	})
}
