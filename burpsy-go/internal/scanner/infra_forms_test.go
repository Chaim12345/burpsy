package scanner

import (
	"net/url"
	"testing"
)

func mustParseForms(t *testing.T, body, page string) []Form {
	t.Helper()
	forms, err := ParseForms([]byte(body), page)
	if err != nil {
		t.Fatalf("ParseForms: %v", err)
	}
	return forms
}

func TestPasswordFieldIsFoundThroughTheFormItBelongsTo(t *testing.T) {
	forms := mustParseForms(t, `
		<form action="/login" method="post"><input type="text" name="u"><input type="password" name="p"></form>
		<form action="/search" method="get"><input type="text" name="q"></form>`,
		"https://app.test/page")

	if len(forms) != 2 {
		t.Fatalf("parsed %d forms, want 2", len(forms))
	}
	if !forms[0].HasPasswordField() {
		t.Error("login form's password field was not found")
	}
	if forms[1].HasPasswordField() {
		t.Error("search form reported a password field it does not have")
	}
}

func TestCleartextSubmissionIsJudgedOnTheResolvedActionNotThePageScheme(t *testing.T) {
	forms := mustParseForms(t,
		`<form action="http://app.test/login" method="post"><input type="password" name="p"></form>`,
		"https://app.test/page")

	if !forms[0].SubmitsOverCleartext() {
		t.Error("an https page posting a password to http:// was not flagged")
	}
}

func TestRelativeActionInheritsThePageScheme(t *testing.T) {
	forms := mustParseForms(t,
		`<form action="/login" method="post"><input type="password" name="p"></form>`,
		"https://app.test/page")

	if forms[0].SubmitsOverCleartext() {
		t.Error("a relative action on an https page was treated as cleartext")
	}
	if forms[0].ActionURL == nil || forms[0].ActionURL.String() != "https://app.test/login" {
		t.Errorf("ActionURL = %v, want https://app.test/login", forms[0].ActionURL)
	}
}

// An absent method attribute means GET, which is the whole point of the row.
func TestAbsentMethodCountsAsGET(t *testing.T) {
	forms := mustParseForms(t, `<form action="/login"><input type="password" name="p"></form>`, "https://app.test/")
	if !forms[0].UsesGET() {
		t.Error("a form with no method attribute was not treated as GET")
	}
	if !forms[0].HasPasswordField() {
		t.Fatal("password field missing")
	}
}

func TestExplicitPostIsNotGET(t *testing.T) {
	forms := mustParseForms(t, `<form action="/login" method="POST"><input type="password" name="p"></form>`, "https://app.test/")
	if forms[0].UsesGET() {
		t.Error("method=POST was reported as GET")
	}
}

// Browsers autocomplete by default, so an absent attribute is enabled, not unknown.
func TestAbsentAutocompleteCountsAsEnabled(t *testing.T) {
	forms := mustParseForms(t, `<form action="/l"><input type="password" name="p"></form>`, "https://app.test/")
	if !forms[0].PasswordAutocompleteEnabled() {
		t.Error("an absent autocomplete attribute was not treated as enabled")
	}
}

func TestFormLevelAutocompleteOffCoversItsPasswordFields(t *testing.T) {
	forms := mustParseForms(t,
		`<form action="/l" autocomplete="off"><input type="password" name="p"></form>`, "https://app.test/")
	if forms[0].PasswordAutocompleteEnabled() {
		t.Error("form-level autocomplete=off did not cover the password field")
	}
}

func TestFieldLevelAutocompleteOffIsHonoured(t *testing.T) {
	forms := mustParseForms(t,
		`<form action="/l"><input type="password" name="p" autocomplete="off"></form>`, "https://app.test/")
	if forms[0].PasswordAutocompleteEnabled() {
		t.Error("field-level autocomplete=off was ignored")
	}
}

func TestCrossDomainPostIsJudgedOnHostname(t *testing.T) {
	page, _ := url.Parse("https://app.test/page")
	forms := mustParseForms(t,
		`<form action="https://evil.test/collect" method="post"><input name="x"></form>
		 <form action="https://app.test/self" method="post"><input name="x"></form>`,
		"https://app.test/page")

	if !forms[0].PostsCrossDomain(page) {
		t.Error("a form posting to another host was not flagged")
	}
	if forms[1].PostsCrossDomain(page) {
		t.Error("a same-host form was flagged as cross-domain")
	}
}

func TestPasswordInURLQueryNeedsANonEmptyValue(t *testing.T) {
	if got := PasswordInURLQuery("https://app.test/l?password=hunter2"); len(got) != 1 {
		t.Errorf("PasswordInURLQuery = %v, want one hit", got)
	}
	if got := PasswordInURLQuery("https://app.test/l?password="); len(got) != 0 {
		t.Errorf("an empty password parameter was reported: %v", got)
	}
	if got := PasswordInURLQuery("https://app.test/l?q=x"); len(got) != 0 {
		t.Errorf("a benign parameter was reported: %v", got)
	}
}

func TestPasswordInCookieNeedsANonEmptyValue(t *testing.T) {
	if !PasswordInCookie("userPassword=hunter2; Path=/") {
		t.Error("a password cookie was not detected")
	}
	if PasswordInCookie("session=abc; Path=/") {
		t.Error("a session cookie was reported as a password cookie")
	}
	if PasswordInCookie("password=; Path=/") {
		t.Error("an empty password cookie was reported")
	}
}

func TestPassportIsNotAPasswordParameter(t *testing.T) {
	if looksLikePasswordParam("passport") || looksLikePasswordParam("passenger") {
		t.Error("a substring match on 'pass' produced a false positive")
	}
}

func TestFieldsOutsideAnyFormAreNotAttributedToOne(t *testing.T) {
	forms := mustParseForms(t,
		`<input type="password" name="stray"><form action="/l"><input name="q"></form>`, "https://app.test/")
	if len(forms) != 1 {
		t.Fatalf("parsed %d forms, want 1", len(forms))
	}
	if forms[0].HasPasswordField() {
		t.Error("a password input outside the form was attributed to it")
	}
}
