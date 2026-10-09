package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestALibraryLoadsGoodSkillsAndCountsTheRefusedOnes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jwt.json", `{"name":"jwt-none","description":"Try alg=none on a JWT","tools":["history","send"],
		"arguments":[{"name":"exchange_id","required":true}],"prompt":"Take exchange {{exchange_id}} and resend it with alg none."}`)
	write(t, dir, "file.json", `{"name":"from-file","description":"Prompt from a file","prompt_file":"p.md"}`)
	write(t, dir, "p.md", "Read the history.")
	write(t, dir, "script.json", `{"name":"scripted","description":"Needs a runtime","prompt":"x","script":"run.js"}`)
	// Refused, each for its own reason.
	write(t, dir, "bad-json.json", `{"name":`)
	write(t, dir, "unknown-field.json", `{"name":"x1","description":"d","prompt":"p","promt":"typo"}`)
	write(t, dir, "no-desc.json", `{"name":"x2","prompt":"p"}`)
	write(t, dir, "both.json", `{"name":"x3","description":"d","prompt":"p","prompt_file":"p.md"}`)
	write(t, dir, "escape.json", `{"name":"x4","description":"d","prompt_file":"../etc/passwd"}`)
	write(t, dir, "undeclared.json", `{"name":"x5","description":"d","prompt":"use {{target}}"}`)
	write(t, dir, "dup.json", `{"name":"jwt-none","description":"again","prompt":"p"}`)
	write(t, dir, "reserved.json", `{"name":"disabled","description":"d","prompt":"p"}`)
	write(t, dir, "notes.txt", "not a manifest")

	lib, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range lib.Skills {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "from-file,jwt-none,scripted" {
		t.Fatalf("loaded %v", names)
	}
	if len(lib.Errors) != 8 {
		t.Fatalf("%d refused manifests, want 8: %+v", len(lib.Errors), lib.Errors)
	}
	for _, want := range []string{"not a skill manifest", "unknown field", "description is required", "exactly one of", "not a path", "not a declared argument", "already defined", "reserved"} {
		found := false
		for _, e := range lib.Errors {
			if strings.Contains(e.Error, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no refusal says %q: %+v", want, lib.Errors)
		}
	}
	if s, _ := lib.Get("from-file"); s.Prompt != "Read the history." {
		t.Fatalf("prompt_file not read: %q", s.Prompt)
	}
	if ok, why := func() (bool, string) { s, _ := lib.Get("scripted"); return s.Available() }(); ok || !strings.Contains(why, "wiwh") {
		t.Fatalf("a script skill is available: %v %q", ok, why)
	}
}

func TestRenderFillsArgumentsAndRefusesHolesAndStrangers(t *testing.T) {
	s := Skill{Name: "s", Prompt: "A {{a}} and {{ b }}.", Arguments: []Argument{{Name: "a", Required: true}, {Name: "b"}}}
	if got, err := s.Render(map[string]string{"a": "1", "b": "2"}); err != nil || got != "A 1 and 2." {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := s.Render(map[string]string{"a": "1"}); got != "A 1 and ." {
		t.Fatalf("optional argument: %q", got)
	}
	if _, err := s.Render(map[string]string{"b": "2"}); err == nil {
		t.Fatal("a missing required argument rendered")
	}
	if _, err := s.Render(map[string]string{"a": "1", "c": "3"}); err == nil {
		t.Fatal("an undeclared argument was accepted")
	}
}

func TestAnUnreadableDirectoryIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing directory loaded")
	}
}
