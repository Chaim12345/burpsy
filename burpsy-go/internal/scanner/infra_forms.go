package scanner

// Form-field analysis for the password-handling and cross-domain-POST catalog rows.
// Substring matching cannot answer these: whether a password input sits inside a form,
// and which form's action it inherits, are tree questions.

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type FormField struct {
	Name         string
	Type         string
	Autocomplete string
}

func (f FormField) IsPassword() bool { return strings.EqualFold(f.Type, "password") }

// AutocompleteEnabled treats an absent attribute as enabled: browsers default to on, so
// silence is permission.
func (f FormField) AutocompleteEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(f.Autocomplete), "off")
}

type Form struct {
	Method       string
	Action       string
	Autocomplete string
	Fields       []FormField
	// ActionURL is Action resolved against the page URL, nil when unresolvable.
	ActionURL *url.URL
}

func (f Form) PasswordFields() []FormField {
	var out []FormField
	for _, fl := range f.Fields {
		if fl.IsPassword() {
			out = append(out, fl)
		}
	}
	return out
}

func (f Form) HasPasswordField() bool { return len(f.PasswordFields()) > 0 }

// UsesGET reports the effective method; HTML defaults to GET when the attribute is absent.
func (f Form) UsesGET() bool {
	m := strings.TrimSpace(f.Method)
	return m == "" || strings.EqualFold(m, "get")
}

// SubmitsOverCleartext reports whether the resolved action target is unencrypted. A form on
// an https page posting to http:// is the "Cleartext submission of password" condition.
func (f Form) SubmitsOverCleartext() bool {
	return f.ActionURL != nil && f.ActionURL.Scheme == "http"
}

// PasswordAutocompleteEnabled reports whether any password field permits autocomplete.
// A form-level autocomplete="off" covers its fields, so both levels are consulted.
func (f Form) PasswordAutocompleteEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(f.Autocomplete), "off") {
		return false
	}
	for _, fl := range f.PasswordFields() {
		if fl.AutocompleteEnabled() {
			return true
		}
	}
	return false
}

// PostsCrossDomain reports whether this form submits to a different host than pageURL.
func (f Form) PostsCrossDomain(pageURL *url.URL) bool {
	if f.ActionURL == nil || pageURL == nil || f.ActionURL.Host == "" {
		return false
	}
	return !strings.EqualFold(f.ActionURL.Hostname(), pageURL.Hostname())
}

// ParseForms extracts every form in body. pageURL resolves relative actions and may be
// empty, in which case relative actions stay unresolved rather than being guessed.
func ParseForms(body []byte, pageURL string) ([]Form, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	var base *url.URL
	if pageURL != "" {
		base, _ = url.Parse(pageURL)
	}

	var forms []Form
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		method, _ := s.Attr("method")
		action, _ := s.Attr("action")
		ac, _ := s.Attr("autocomplete")
		f := Form{Method: method, Action: action, Autocomplete: ac}

		if action != "" {
			if u, err := url.Parse(action); err == nil {
				if base != nil {
					f.ActionURL = base.ResolveReference(u)
				} else if u.IsAbs() {
					f.ActionURL = u
				}
			}
		} else if base != nil {
			// An empty action submits to the page itself.
			f.ActionURL = base
		}

		s.Find("input,select,textarea").Each(func(_ int, in *goquery.Selection) {
			name, _ := in.Attr("name")
			typ, _ := in.Attr("type")
			iac, _ := in.Attr("autocomplete")
			f.Fields = append(f.Fields, FormField{Name: name, Type: typ, Autocomplete: iac})
		})
		forms = append(forms, f)
	})
	return forms, nil
}

// PasswordInURLQuery reports password-like parameter names carrying a value in a URL query.
func PasswordInURLQuery(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var hits []string
	for name, vals := range u.Query() {
		if !looksLikePasswordParam(name) {
			continue
		}
		for _, v := range vals {
			if v != "" {
				hits = append(hits, name)
				break
			}
		}
	}
	return hits
}

// PasswordInCookie reports password-like cookie names carrying a value.
func PasswordInCookie(setCookie string) bool {
	name, value, ok := strings.Cut(setCookie, "=")
	if !ok {
		return false
	}
	value, _, _ = strings.Cut(value, ";")
	return looksLikePasswordParam(strings.TrimSpace(name)) && strings.TrimSpace(value) != ""
}

func looksLikePasswordParam(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "password", "passwd", "pass", "pwd", "passwrd", "userpassword", "user_password", "pw":
		return true
	}
	// "password_confirmation", "oldPassword". Excludes "passport"/"passenger".
	return strings.Contains(n, "password") || strings.Contains(n, "passwd") || strings.Contains(n, "pwd")
}
