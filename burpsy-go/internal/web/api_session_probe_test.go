package web

import "testing"

// The parameter names a login probe reports feed MatchingRuleFor's parameter axis, so a name
// the request does not actually carry can make a param-scoped session rule match a request it
// should not. These pin where the names may come from: the URL query always, the body only
// when the step's own Content-Type says form-urlencoded (burpsy-react-ui-zqrm, finding 1).

func TestProbeParamNamesReadBodyPairsOnlyWhenTheStepSaysForm(t *testing.T) {
	step := sessionStepDto{
		URL:  "https://app.test/login?next=/home",
		Body: "user=admin&pass=hunter2",
		Headers: [][2]string{
			{"Content-Type", "application/x-www-form-urlencoded"},
		},
	}
	got := probeParamNames(step)
	want := map[string]bool{"next": true, "user": true, "pass": true}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want exactly %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected parameter name %q in %v", n, got)
		}
	}
}

func TestProbeParamNamesDoesNotReadPairsOutOfAJSONBody(t *testing.T) {
	// The body carries "=" twice — inside string values that are URLs with their own query
	// strings. Reading it as a form would yield "state" and "csrf_token" as parameter names
	// the request does not carry, and a rule scoped to one of those names would then match
	// this request. Reported against abb9bd8, where the body was read whenever it contained
	// an "=" at all.
	step := sessionStepDto{
		URL:  "https://app.test/login",
		Body: `{"redirect_uri":"https://x/cb?csrf_token=abc&state=xyz"}`,
		Headers: [][2]string{
			{"Content-Type", "application/json"},
		},
	}
	for _, name := range probeParamNames(step) {
		if name == "state" || name == "csrf_token" {
			t.Errorf("JSON body yielded spurious parameter name %q — a body parameter must come from a form body only", name)
		}
	}
}

func TestProbeParamNamesWithNoContentTypeReadsTheQueryAlone(t *testing.T) {
	// An unlabelled body is not a form by default: the same treatment Burp's parameter scope
	// gives it, and the safe reading of a request this layer cannot classify.
	step := sessionStepDto{
		URL:  "https://app.test/login?id=7",
		Body: "user=admin&pass=hunter2",
	}
	got := probeParamNames(step)
	if len(got) != 1 || got[0] != "id" {
		t.Errorf("names = %v, want only the URL query's id — a body with no Content-Type is not a form", got)
	}
}
