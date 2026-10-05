package scanner

import (
	"strings"
	"testing"
)

func TestSecretsModuleDetectsAWSAccessKeyID(t *testing.T) {
	m := &SecretsModule{}
	body := []byte(`{"debug_config":"AKIAABCDEFGHIJKLMNOP"}`)
	findings := m.Analyze(body, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	// Through the gitleaks corpus since 8j0d: its aws-access-token rule replaced the hand-written one.
	if findings[0].Name != "Secret exposed: AWS access token" {
		t.Errorf("unexpected finding name %q", findings[0].Name)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %q", findings[0].Severity)
	}
}

func TestSecretsModuleDetectsAWSSecretKey(t *testing.T) {
	m := &SecretsModule{}
	body := []byte(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	findings := m.Analyze(body, nil)
	if len(findings) != 1 || findings[0].Name != "AWS secret access key exposed" {
		t.Fatalf("expected AWS secret key finding, got %+v", findings)
	}
	if strings.Contains(findings[0].Evidence, "wJalrXUtnFEMI") {
		t.Errorf("evidence should be redacted, got %q", findings[0].Evidence)
	}
}

// A JWT in a response is how every login works, not a leak: the module does not report one
// (excludedGitleaksRules), and burpsy's JWT checks read tokens for the weaknesses that are findings.
func TestSecretsModuleDoesNotReportAJWTAsALeak(t *testing.T) {
	m := &SecretsModule{}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	body := []byte(`{"token":"` + jwt + `"}`)
	if findings := m.Analyze(body, nil); len(findings) != 0 {
		t.Fatalf("a session JWT was reported as a leaked secret: %+v", findings)
	}
}

// A provider token is named by its provider — the corpus knows sk_live_ is Stripe — rather than as a
// generic "API key", and its finding names the rule and where in the body it was.
func TestSecretsModuleNamesAProviderTokenByItsProvider(t *testing.T) {
	m := &SecretsModule{}
	body := []byte("{\n  \"api_key\": \"sk_live_abcdefghijklmnop1234\"}")
	findings := m.Analyze(body, nil)
	if len(findings) != 1 || findings[0].Name != "Secret exposed: Stripe access token" {
		t.Fatalf("expected one Stripe finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "stripe-access-token") || !strings.Contains(findings[0].Detail, "line 2") {
		t.Errorf("detail does not name the rule and the location: %q", findings[0].Detail)
	}
	if strings.Contains(findings[0].Evidence, "abcdefghijklmnop") {
		t.Errorf("evidence is not redacted: %q", findings[0].Evidence)
	}
}

func TestSecretsModuleDetectsGCPServiceAccount(t *testing.T) {
	m := &SecretsModule{}
	body := []byte(`{"type": "service_account", "project_id": "my-project"}`)
	findings := m.Analyze(body, nil)
	if len(findings) != 1 || findings[0].Name != "GCP service account key exposed" {
		t.Fatalf("expected GCP finding, got %+v", findings)
	}
}

func TestSecretsModuleDetectsAzureStorageConnectionString(t *testing.T) {
	m := &SecretsModule{}
	body := []byte(`DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=abcd1234ABCD5678efgh9012IJKL3456mnop==;EndpointSuffix=core.windows.net`)
	findings := m.Analyze(body, nil)
	// One finding: the corpus's generic rule also matches the AccountKey, and yields to the provider
	// rule that names it.
	if len(findings) != 1 || findings[0].Name != "Azure storage account key exposed" {
		t.Fatalf("expected Azure finding, got %+v", findings)
	}
}

func TestSecretsModuleReturnsNoFindingsOnCleanBody(t *testing.T) {
	m := &SecretsModule{}
	findings := m.Analyze([]byte(`{"status":"ok","message":"hello world"}`), nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestAuthModuleDetectsLoginForm(t *testing.T) {
	m := &AuthModule{}
	body := []byte(`<html><body><form action="/login" method="post">
		<input type="text" name="username">
		<input type="password" name="password">
		<button type="submit">Log in</button>
	</form></body></html>`)
	findings := m.Analyze(body, nil)
	if !containsFinding(findings, "Login form detected") {
		t.Fatalf("expected login form finding, got %+v", findings)
	}
}

func TestAuthModuleDetects401(t *testing.T) {
	m := &AuthModule{}
	raw := []byte("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"unauthorized\"}")
	findings := m.Analyze(raw, nil)
	if !containsFinding(findings, "Authentication required") {
		t.Fatalf("expected 401 finding, got %+v", findings)
	}
}

func TestAuthModuleDetects403(t *testing.T) {
	m := &AuthModule{}
	raw := []byte("HTTP/1.1 403 Forbidden\r\n\r\n")
	findings := m.Analyze(raw, nil)
	if !containsFinding(findings, "Access forbidden") {
		t.Fatalf("expected 403 finding, got %+v", findings)
	}
}

func TestAuthModuleDetectsStatusFromHeaderOverride(t *testing.T) {
	m := &AuthModule{}
	findings := m.Analyze([]byte("no status line here"), map[string]string{"status": "401"})
	if !containsFinding(findings, "Authentication required") {
		t.Fatalf("expected 401 finding from header override, got %+v", findings)
	}
}

func TestAuthModuleDetectsRedirectToLogin(t *testing.T) {
	m := &AuthModule{}
	headers := map[string]string{"location": "/account/login?returnUrl=/dashboard"}
	findings := m.Analyze([]byte("HTTP/1.1 302 Found\r\n\r\n"), headers)
	if !containsFinding(findings, "Redirect to login page") {
		t.Fatalf("expected redirect-to-login finding, got %+v", findings)
	}
}

func TestAuthModuleDetectsSessionCookie(t *testing.T) {
	m := &AuthModule{}
	headers := map[string]string{headerSetCookie: "JSESSIONID=A1B2C3D4E5F6; Path=/; HttpOnly"}
	findings := m.Analyze([]byte("HTTP/1.1 200 OK\r\n\r\n"), headers)
	if !containsFinding(findings, "Session cookie observed") {
		t.Fatalf("expected session cookie finding, got %+v", findings)
	}
}

func TestAuthModuleReturnsNoFindingsOnPlainOKResponse(t *testing.T) {
	m := &AuthModule{}
	findings := m.Analyze([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"), nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestFingerprintModuleDetectsTechnologyFromHeaders(t *testing.T) {
	m := &FingerprintModule{}
	headers := map[string]string{"Server": "nginx/1.18.0"}
	findings := m.Analyze([]byte("<html></html>"), headers)
	if !containsFindingPrefix(findings, "Technology detected: Nginx") {
		t.Fatalf("expected nginx fingerprint finding, got %+v", findings)
	}
}

func TestFingerprintModuleDetectsWordPressFromBody(t *testing.T) {
	m := &FingerprintModule{}
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.4"></head><body></body></html>`)
	findings := m.Analyze(body, nil)
	if !containsFindingPrefix(findings, "Technology detected: WordPress") {
		t.Fatalf("expected WordPress fingerprint finding, got %+v", findings)
	}
}

func TestFingerprintModuleReturnsNoFindingsOnUnrecognizableResponse(t *testing.T) {
	m := &FingerprintModule{}
	findings := m.Analyze([]byte("just some plain unrecognizable text"), nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestDefaultResponseModulesReturnsThreeModules(t *testing.T) {
	modules := DefaultResponseModules()
	if len(modules) != 3 {
		t.Fatalf("expected 3 default modules, got %d", len(modules))
	}
	names := map[string]bool{}
	for _, m := range modules {
		names[m.Name()] = true
	}
	for _, want := range []string{"secrets", "auth", "fingerprint"} {
		if !names[want] {
			t.Errorf("expected module %q in default set, got %v", want, names)
		}
	}
}

func TestRunResponseModulesAggregatesFindingsAcrossModules(t *testing.T) {
	body := []byte(`{"api_key": "sk_live_abcdefghijklmnop1234"}` + "\r\n" +
		`<form><input type="password"></form>`)
	headers := map[string]string{"Server": "nginx"}
	findings := RunResponseModules(DefaultResponseModules(), body, headers)
	if !containsFinding(findings, "Secret exposed: Stripe access token") {
		t.Errorf("expected secrets finding, got %+v", findings)
	}
	if !containsFinding(findings, "Login form detected") {
		t.Errorf("expected auth finding, got %+v", findings)
	}
	if !containsFindingPrefix(findings, "Technology detected: Nginx") {
		t.Errorf("expected fingerprint finding, got %+v", findings)
	}
}

func TestRunResponseModulesSkipsNilModule(t *testing.T) {
	modules := []ResponseModule{nil, &SecretsModule{}}
	findings := RunResponseModules(modules, []byte("nothing interesting"), nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings and no panic, got %+v", findings)
	}
}

func containsFinding(findings []ResponseFinding, name string) bool {
	for _, f := range findings {
		if f.Name == name {
			return true
		}
	}
	return false
}

func containsFindingPrefix(findings []ResponseFinding, prefix string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.Name, prefix) {
			return true
		}
	}
	return false
}
