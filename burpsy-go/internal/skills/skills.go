// Package skills loads the operator's skill library (burpsy-react-ui-ulsy): packaged prompt
// techniques an agent invokes, each naming the tools it calls.
//
// Burp's agent surface has skills — PortSwigger-packaged techniques run with run_skill_script, listed
// in the client with the tools they use (desktop/burp-at/skills.html). burpsy's equivalent is a
// directory the OPERATOR names at start (`burpsy -skills DIR`); no route takes a path, so nothing an
// agent sends can make the console read a file it was not pointed at.
//
// A skill is one `<name>.json` manifest in that directory:
//
//	{"name": "jwt-none-alg", "description": "…", "tools": ["history", "send"],
//	 "arguments": [{"name": "exchange_id", "description": "…", "required": true}],
//	 "prompt": "Take exchange {{exchange_id}} …"}            // or "prompt_file": "jwt.md"
//
// Prompt-only skills are served (the MCP transport publishes them as MCP prompts). A manifest naming a
// "script" is loaded and listed as UNAVAILABLE with its reason: script-bearing skills run through the
// scripting runtime (burpsy-react-ui-wiwh), which this build does not have — listed, not dropped,
// because a skill that silently vanished would read as a library that never had it.
//
// A manifest that cannot be read is refused and COUNTED: the library reports every refused file with
// its reason, so "3 skills" never hides "and 2 that did not load".
package skills

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Argument is one value a skill's prompt takes.
type Argument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Skill is one loaded manifest.
type Skill struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Tools       []string   `json:"tools"`
	Arguments   []Argument `json:"arguments"`
	// Prompt is the prompt text, read from prompt or prompt_file.
	Prompt string `json:"-"`
	// Script is the script file a script-bearing skill names; non-empty makes the skill unavailable.
	Script string `json:"script,omitempty"`
	// File is the manifest's file name within the library directory.
	File string `json:"file"`
}

// Available reports whether this build can run the skill, and why not.
func (s Skill) Available() (bool, string) {
	if s.Script != "" {
		return false, "a script-bearing skill runs through the scripting runtime (burpsy-react-ui-wiwh), which this build does not have"
	}
	return true, ""
}

// LoadError is one refused manifest.
type LoadError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// Library is a loaded skills directory.
type Library struct {
	Dir    string
	Skills []Skill
	Errors []LoadError
}

// Get returns the named skill.
func (l *Library) Get(name string) (Skill, bool) {
	if l == nil {
		return Skill{}, false
	}
	for _, s := range l.Skills {
		if s.Name == name {
			return s, true
		}
	}
	return Skill{}, false
}

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	argPattern  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`)
	placeholder = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
)

// reservedNames are names a skill cannot take because a console route spells them.
var reservedNames = map[string]bool{"disabled": true}

// maxPromptBytes bounds one prompt; a skill is a technique, not a document.
const maxPromptBytes = 256 << 10

type manifest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Tools       []string   `json:"tools"`
	Arguments   []Argument `json:"arguments"`
	Prompt      string     `json:"prompt"`
	PromptFile  string     `json:"prompt_file"`
	Script      string     `json:"script"`
}

// plainFile reports whether name is a file name in the directory itself, not a path out of it.
func plainFile(name string) bool {
	return name != "" && name == filepath.Base(name) && name != "." && name != ".." && !strings.ContainsAny(name, `/\`)
}

// Load reads every *.json manifest in dir. The error is for a directory that cannot be read at all;
// a bad manifest is a LoadError in the library, not a failure to load the rest.
func Load(dir string) (*Library, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("skills: %w", err)
	}
	lib := &Library{Dir: dir, Skills: []Skill{}, Errors: []LoadError{}}
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		sk, err := loadOne(dir, e.Name())
		if err == nil {
			if prev, dup := seen[sk.Name]; dup {
				err = fmt.Errorf("skill %q is already defined by %s", sk.Name, prev)
			}
		}
		if err != nil {
			lib.Errors = append(lib.Errors, LoadError{File: e.Name(), Error: err.Error()})
			continue
		}
		seen[sk.Name] = e.Name()
		lib.Skills = append(lib.Skills, sk)
	}
	sort.Slice(lib.Skills, func(i, j int) bool { return lib.Skills[i].Name < lib.Skills[j].Name })
	return lib, nil
}

func loadOne(dir, file string) (Skill, error) {
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return Skill{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m manifest
	if err := dec.Decode(&m); err != nil {
		return Skill{}, fmt.Errorf("not a skill manifest: %w", err)
	}
	switch {
	case !namePattern.MatchString(m.Name):
		return Skill{}, fmt.Errorf("name %q must be 1-64 of a-z, 0-9, '-' and '_', starting with a letter or digit", m.Name)
	case reservedNames[m.Name]:
		return Skill{}, fmt.Errorf("name %q is reserved", m.Name)
	case strings.TrimSpace(m.Description) == "":
		return Skill{}, fmt.Errorf("description is required: it is what an agent chooses a skill by")
	case (m.Prompt == "") == (m.PromptFile == ""):
		return Skill{}, fmt.Errorf("exactly one of prompt and prompt_file is required")
	}
	prompt := m.Prompt
	if m.PromptFile != "" {
		if !plainFile(m.PromptFile) {
			return Skill{}, fmt.Errorf("prompt_file %q must be a file in the skills directory, not a path", m.PromptFile)
		}
		b, err := os.ReadFile(filepath.Join(dir, m.PromptFile))
		if err != nil {
			return Skill{}, fmt.Errorf("prompt_file: %w", err)
		}
		prompt = string(b)
	}
	if len(prompt) > maxPromptBytes {
		return Skill{}, fmt.Errorf("the prompt is %d bytes; the bound is %d", len(prompt), maxPromptBytes)
	}
	if m.Script != "" && !plainFile(m.Script) {
		return Skill{}, fmt.Errorf("script %q must be a file in the skills directory, not a path", m.Script)
	}
	declared := map[string]bool{}
	for _, a := range m.Arguments {
		if !argPattern.MatchString(a.Name) {
			return Skill{}, fmt.Errorf("argument name %q is not an identifier", a.Name)
		}
		if declared[a.Name] {
			return Skill{}, fmt.Errorf("argument %q is declared twice", a.Name)
		}
		declared[a.Name] = true
	}
	for _, p := range placeholder.FindAllStringSubmatch(prompt, -1) {
		if !declared[p[1]] {
			return Skill{}, fmt.Errorf("the prompt uses {{%s}}, which is not a declared argument", p[1])
		}
	}
	tools := m.Tools
	if tools == nil {
		tools = []string{}
	}
	args := m.Arguments
	if args == nil {
		args = []Argument{}
	}
	return Skill{Name: m.Name, Description: strings.TrimSpace(m.Description), Tools: tools, Arguments: args,
		Prompt: prompt, Script: m.Script, File: file}, nil
}

// Render fills the prompt's {{argument}} placeholders. A required argument that is missing, or an
// argument the skill does not declare, is an error: a prompt with a hole in it, or one silently
// ignoring what the caller passed, is not the technique the operator packaged.
func (s Skill) Render(args map[string]string) (string, error) {
	declared := map[string]Argument{}
	for _, a := range s.Arguments {
		declared[a.Name] = a
	}
	for k := range args {
		if _, ok := declared[k]; !ok {
			return "", fmt.Errorf("skill %s takes no argument %q", s.Name, k)
		}
	}
	for _, a := range s.Arguments {
		if a.Required && strings.TrimSpace(args[a.Name]) == "" {
			return "", fmt.Errorf("skill %s needs argument %q", s.Name, a.Name)
		}
	}
	return placeholder.ReplaceAllStringFunc(s.Prompt, func(m string) string {
		return args[placeholder.FindStringSubmatch(m)[1]]
	}), nil
}
