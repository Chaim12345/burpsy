package session

import (
	"encoding/json"
	"strings"
	"testing"
)

// burpRecorderSample is shaped exactly like the "Login Recorder for Burp Suite" output: the start
// header the service worker writes first, an address-bar goto, then the content script's click /
// typing / keyboard events with their element attributes (Recorder.js createEvent), a wait from the
// recording delay, and the noise events the recorder also emits.
const burpRecorderSample = `[
  {"name":"Login Recorder for Burp Suite","version":"2.4.1","recordingDelay":1,"eventType":"start",
   "platform":"Linux x86_64","iframes":[],"windows":[{"windowId":1}],"tabs":[{"tabId":2,"windowId":1}]},
  {"date":"2026-10-08T10:00:00.000Z","timestamp":1,"eventType":"goto","url":"https://app.example/login",
   "triggersNavigation":true,"frameId":0,"tabId":2,"windowId":1,"fromAddressBar":true},
  {"eventType":"click","tagName":"INPUT","id":"username","name":"user","elementType":"text",
   "xPath":"/html/body/form/input[1]","frameId":0,"isShadowElement":false},
  {"eventType":"typing","tagName":"INPUT","id":"username","name":"user","elementType":"text",
   "typedValue":"alice","xPath":"/html/body/form/input[1]","frameId":0},
  {"eventType":"wait","durationInMillis":25000},
  {"eventType":"typing","tagName":"INPUT","id":"","name":"pass","elementType":"password",
   "typedValue":"hunter2","xPath":"/html/body/form/input[2]","frameId":0},
  {"eventType":"scroll","scrollX":0,"scrollY":300},
  {"eventType":"keyboard","key":"Enter","shiftKey":false},
  {"eventType":"userNavigate","url":"https://app.example/mfa"},
  {"eventType":"typing","tagName":"INPUT","id":"otp","name":"otp","elementType":"text",
   "typedValue":"492039","xPath":"/html/body/form/input","frameId":0},
  {"eventType":"click","tagName":"BUTTON","id":"","name":"","xPath":"/html/body/form/button","frameId":0},
  {"eventType":"click","tagName":"A","id":"inner","frameId":3,"xPath":"/html/body/a"}
]`

func TestImportBurpLoginRecorderScript(t *testing.T) {
	res, err := ImportScript([]byte(burpRecorderSample))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "burp-login-recorder" || res.Name != "Login Recorder for Burp Suite" {
		t.Fatalf("format %q name %q", res.Format, res.Name)
	}
	want := []LoginStep{
		{Kind: StepGoto, URL: "https://app.example/login"},
		{Kind: StepClick, Selector: "#username", XPath: "/html/body/form/input[1]"},
		{Kind: StepType, Selector: "#username", XPath: "/html/body/form/input[1]", Value: "alice"},
		{Kind: StepWait, WaitMS: 10000},
		{Kind: StepType, Selector: `input[name="pass"]`, XPath: "/html/body/form/input[2]", Value: "hunter2", Secret: true},
		{Kind: StepKey, Key: "Enter"},
		{Kind: StepType, Selector: "#otp", XPath: "/html/body/form/input", Value: "492039"},
		{Kind: StepClick, XPath: "/html/body/form/button"},
	}
	if len(res.Steps) != len(want) {
		t.Fatalf("got %d steps, want %d: %+v", len(res.Steps), len(want), res.Steps)
	}
	for i := range want {
		got, _ := json.Marshal(res.Steps[i])
		exp, _ := json.Marshal(want[i])
		if string(got) != string(exp) {
			t.Errorf("step %d:\n got %s\nwant %s", i+1, got, exp)
		}
	}
	// Every event that did not become a step as recorded is named — nothing silently dropped.
	byEvent := map[int]ImportNote{}
	for _, n := range res.Notes {
		byEvent[n.Event] = n
	}
	for ev, outcome := range map[int]string{5: "warning", 7: "dropped", 9: "dropped", 10: "warning", 12: "dropped"} {
		n, ok := byEvent[ev]
		if !ok || n.Outcome != outcome {
			t.Errorf("event %d: want a %s note, got %+v", ev, outcome, n)
		}
	}
	if !strings.Contains(byEvent[10].Detail, "TOTP") {
		t.Errorf("the one-time-code typing should suggest a TOTP step: %q", byEvent[10].Detail)
	}
	if !strings.Contains(byEvent[12].Detail, "iframe") {
		t.Errorf("the iframe click should say why: %q", byEvent[12].Detail)
	}
}

func TestImportChromeRecorderExport(t *testing.T) {
	doc := `{"title":"login","steps":[
	  {"type":"setViewport","width":1280,"height":800},
	  {"type":"navigate","url":"https://app.example/"},
	  {"type":"click","selectors":[["aria/Sign in"],["#signin"],["xpath///*[@id=\"signin\"]"]]},
	  {"type":"change","value":"s3cret","selectors":[["#password"]]},
	  {"type":"keyDown","key":"Enter"},{"type":"keyUp","key":"Enter"},
	  {"type":"waitForElement","selectors":[["#home"]]}]}`
	res, err := ImportScript([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "chrome-recorder" || len(res.Steps) != 4 {
		t.Fatalf("format %q steps %+v", res.Format, res.Steps)
	}
	if res.Steps[1].Selector != "#signin" || res.Steps[1].XPath != `//*[@id="signin"]` {
		t.Errorf("click locators: %+v", res.Steps[1])
	}
	if !res.Steps[2].Secret {
		t.Errorf("a change into #password should be marked secret: %+v", res.Steps[2])
	}
	if len(res.Notes) != 2 {
		t.Errorf("setViewport and waitForElement must each be noted, got %+v", res.Notes)
	}
}

func TestRecordedLoginViewNeverCarriesASecret(t *testing.T) {
	rl := &RecordedLogin{ID: "x", Label: "admin", Steps: []LoginStep{
		{Kind: StepGoto, URL: "https://app.example/login"},
		{Kind: StepType, Selector: "#u", Value: "alice"},
		{Kind: StepType, Selector: "#p", Value: "hunter2", Secret: true},
		{Kind: StepTOTP, Selector: "#otp", TOTP: &TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Algorithm: TOTPSHA1, Period: 30, Digits: 6}},
	}, StatusCheck: &StatusCheck{URL: "https://app.example/me", Text: "Sign out"}}
	if err := rl.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rl.View())
	out := string(b)
	for _, secret := range []string{"hunter2", "JBSWY3DPEHPK3PXP"} {
		if strings.Contains(out, secret) {
			t.Fatalf("view leaked %q: %s", secret, out)
		}
	}
	for _, want := range []string{`"value":"alice"`, `"has_value":true`, `"has_secret":true`,
		`"description":"Type a secret value into #p"`, `"description":"Type TOTP code into #otp"`} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %s: %s", want, out)
		}
	}
}

// The "See as JSON" round trip: the view goes out, comes back unchanged, and the stored secrets
// survive. An edit that moves a secret step, or a view with no stored secret behind it, is refused.
func TestMergeSecretsKeepsRedactedSecretsByPosition(t *testing.T) {
	stored := []LoginStep{
		{Kind: StepGoto, URL: "https://app.example/login"},
		{Kind: StepType, Selector: "#p", Value: "hunter2", Secret: true},
		{Kind: StepTOTP, Selector: "#otp", TOTP: &TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Period: 30, Digits: 6}},
	}
	rl := &RecordedLogin{Steps: stored}
	view, _ := json.Marshal(rl.View().Steps)
	var back []IncomingStep
	if err := json.Unmarshal(view, &back); err != nil {
		t.Fatal(err)
	}
	merged, err := MergeSecrets(back, stored)
	if err != nil {
		t.Fatal(err)
	}
	if merged[1].Value != "hunter2" || merged[2].TOTP.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secrets lost in the round trip: %+v / %+v", merged[1], merged[2].TOTP)
	}
	// Swap the two secret steps: the positions no longer line up, so nothing is guessed.
	back[1], back[2] = back[2], back[1]
	if _, err := MergeSecrets(back, stored); err == nil {
		t.Fatal("a moved secret step must be refused rather than given the wrong stored secret")
	}
}

func TestRecordedLoginValidation(t *testing.T) {
	base := func() *RecordedLogin {
		return &RecordedLogin{Label: "l", Steps: []LoginStep{{Kind: StepGoto, URL: "https://a.example/"}}}
	}
	cases := map[string]func(*RecordedLogin){
		"step 1 must be a goto": func(r *RecordedLogin) { r.Steps[0] = LoginStep{Kind: StepWait} },
		"a status check is required when using TOTP steps": func(r *RecordedLogin) {
			r.Steps = append(r.Steps, LoginStep{Kind: StepTOTP, Selector: "#o", TOTP: &TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Period: 30, Digits: 6}})
		},
		"needs a selector or an XPath": func(r *RecordedLogin) { r.Steps = append(r.Steps, LoginStep{Kind: StepClick}) },
		"is not one this replay can press": func(r *RecordedLogin) {
			r.Steps = append(r.Steps, LoginStep{Kind: StepKey, Key: "Hyper"})
		},
		"confirmation text is empty": func(r *RecordedLogin) { r.StatusCheck = &StatusCheck{URL: "https://a.example/me"} },
		"needs a label":              func(r *RecordedLogin) { r.Label = " " },
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("minimal sequence refused: %v", err)
	}
	for want, mutate := range cases {
		r := base()
		mutate(r)
		err := r.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}
