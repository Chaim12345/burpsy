package intruder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const openAPISampleSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "sample", "version": "1.0"},
  "paths": {
    "/widgets/{id}": {
      "get": {
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "q", "in": "query", "schema": {"type": "string"}},
          {"name": "email", "in": "query", "schema": {"type": "string", "format": "email"}},
          {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "closed"]}},
          {"name": "tags", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}}
        ]
      }
    }
  }
}`

func TestOpenAPIPayloadsGeneratesOneFamilyPerDeclaredParameterType(t *testing.T) {
	wire, err := json.Marshal(map[string]any{"type": "openapi_payloads", "spec": openAPISampleSpec})
	if err != nil {
		t.Fatal(err)
	}
	s := mustResolve(t, string(wire), 10000)
	got := strs(s)
	if len(got) == 0 {
		t.Fatal("expected payloads, got none")
	}

	has := func(want string) bool {
		for _, g := range got {
			if g == want {
				return true
			}
		}
		return false
	}

	// integer boundary values (parameter "id")
	for _, want := range []string{"0", "-1", maxInt64Str, maxInt64Plus1Str} {
		if !has(want) {
			t.Errorf("integer boundary value %q missing from %v", want, got)
		}
	}
	// email format violations (parameter "email")
	if !has("not-an-email") || !has("user@") {
		t.Errorf("email format violation payloads missing from %v", got)
	}
	// out-of-enum values (parameter "status", enum ["open","closed"])
	if !has("__not_in_enum__") {
		t.Errorf("out-of-enum payload missing from %v", got)
	}
	for _, forbidden := range []string{"open", "closed"} {
		if has(forbidden) {
			t.Errorf("enum payload set must never include a declared enum value, got %q in %v", forbidden, got)
		}
	}
	// array shapes (parameter "tags")
	if !has("[]") || !has("[[[[[1]]]]]") {
		t.Errorf("array shape payloads missing from %v", got)
	}
	// string fuzzing corpus (parameter "q", plain string with no format/enum)
	fuzzLines, err := builtinWordlistLines("burp-fuzzing-full")
	if err != nil {
		t.Fatal(err)
	}
	if len(fuzzLines) == 0 {
		t.Fatal("burp-fuzzing-full wordlist is empty")
	}
	if !has(fuzzLines[0]) {
		t.Errorf("string parameter should draw from burp-fuzzing-full, first line %q not found in %v", fuzzLines[0], got[:min(len(got), 20)])
	}
}

func TestOpenAPIPayloadsReadsFromAPathWhenSpecIsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, []byte(openAPISampleSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(map[string]any{"type": "openapi_payloads", "path": path})
	if err != nil {
		t.Fatal(err)
	}
	s := mustResolve(t, string(wire), 10000)
	if s.Count == 0 {
		t.Fatal("expected payloads read from path, got none")
	}
}

func TestOpenAPIPayloadsParamNameRestrictsToOneParameter(t *testing.T) {
	wire, err := json.Marshal(map[string]any{"type": "openapi_payloads", "spec": openAPISampleSpec, "param_name": "email"})
	if err != nil {
		t.Fatal(err)
	}
	s := mustResolve(t, string(wire), 10000)
	got := strs(s)
	for _, g := range got {
		if g == "0" || g == "-1" || g == "[]" {
			t.Errorf("param_name=email must not emit other parameters' payloads, got %q in %v", g, got)
		}
	}
	found := false
	for _, g := range got {
		if g == "not-an-email" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected email violation payloads, got %v", got)
	}
}

func TestOpenAPIPayloadsRefusesWhenNeitherSpecNorPathIsSet(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"openapi_payloads"}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("no spec and no path must be refused")
	}
}

func TestOpenAPIPayloadsRefusesAnUnreadableSpec(t *testing.T) {
	wire, err := json.Marshal(map[string]any{"type": "openapi_payloads", "spec": `{"not": "a definition"}`})
	if err != nil {
		t.Fatal(err)
	}
	var src PayloadSource
	if err := json.Unmarshal(wire, &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("an unreadable/non-OpenAPI document must be refused, not read as an empty parameter set")
	} else if !strings.Contains(err.Error(), "openapi_payloads") {
		t.Errorf("refusal should name the generator: %v", err)
	}
}

func TestOpenAPIPayloadsRefusesAParamNameTheDefinitionNeverDeclared(t *testing.T) {
	wire, err := json.Marshal(map[string]any{"type": "openapi_payloads", "spec": openAPISampleSpec, "param_name": "does_not_exist"})
	if err != nil {
		t.Fatal(err)
	}
	var src PayloadSource
	if err := json.Unmarshal(wire, &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("a param_name naming no declared parameter must be refused")
	}
}
