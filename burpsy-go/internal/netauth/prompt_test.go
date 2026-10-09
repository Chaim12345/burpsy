package netauth

import "testing"

func TestFailuresAreRecordedOnlyWhilePromptingAndOnlyForPlatformSchemes(t *testing.T) {
	c := NewCredentials()
	c.Learn("a.test", `Basic realm="r"`)
	if len(c.Failures()) != 0 {
		t.Fatal("recorded with the prompt off")
	}
	c.SetPromptOnFailure(true)
	c.Learn("a.test", `Bearer realm="api"`)
	if len(c.Failures()) != 0 {
		t.Fatal("a Bearer challenge is not a platform-authentication failure")
	}
	c.Learn("a.test", `Basic realm="r"`)
	c.Learn("a.test", `Basic realm="r"`)
	f := c.Failures()
	if len(f) != 1 || f[0].Reason != FailureNoCredential || f[0].Count != 2 || f[0].Realm != "r" || f[0].Scheme != "Basic" {
		t.Fatalf("failures = %+v", f)
	}

	// A rule for the host clears its failure; the host refusing that rule records a rejection.
	rule, err := NewCredential("a.test", SchemeBasic, "u", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	c.Add(rule)
	if len(c.Failures()) != 0 {
		t.Fatal("adding a credential for the host did not clear its failure")
	}
	c.Learn("a.test", `Basic realm="r"`)
	if f := c.Failures(); len(f) != 1 || f[0].Reason != FailureRejected {
		t.Fatalf("after a covered host refused its Basic credential: %+v", f)
	}

	if !c.DismissFailure("A.TEST") || len(c.Failures()) != 0 || c.DismissFailure("a.test") {
		t.Error("dismissing by host did not forget exactly that failure")
	}
	c.Learn("b.test", `NTLM`)
	c.SetPromptOnFailure(false)
	if len(c.Failures()) != 0 {
		t.Error("turning the prompt off kept recorded failures")
	}
}

func TestTheFailureListIsBounded(t *testing.T) {
	c := NewCredentials()
	c.SetPromptOnFailure(true)
	for i := 0; i < maxAuthFailures+10; i++ {
		c.Learn(string(rune('a'+i%26))+string(rune('a'+i/26))+".test", `Basic realm="r"`)
	}
	if n := len(c.Failures()); n != maxAuthFailures {
		t.Errorf("%d failures kept, want the bound %d", n, maxAuthFailures)
	}
}
