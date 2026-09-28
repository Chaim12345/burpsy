package crawler

import (
	"encoding/json"
	"fmt"
)

// Burp's `crawler/error_handling` family: what a crawl does about requests that FAIL, rather than
// only counting them (burpsy-react-ui-o0c5).
//
// Four keys, and burpsy had none of them:
//
//	pause_task_requests_timed_out_count
//	pause_task_requests_timed_out_percentage
//	consecutive_authentication_failures_before_pausing_task
//	number_of_follow_up_passes
//
// Two of Burp's shipped configurations name three of them by value, so importing either was a silent
// no-op that burpsy honestly reported as "unapplied" — the exact failure burpsy-react-ui-3ok6 was
// filed for, unfixed. And a flaky target produced a crawl that reported N transport failures with a
// hole in its coverage and no way to ask for a second pass over just those requests.
//
// # THE ZERO IS THE FEATURE
//
// Burp ships "Never stop crawl due to application errors.json", and it is spelled:
//
//	"error_handling": {
//	  "number_of_follow_up_passes": 1,
//	  "pause_task_requests_timed_out_count": 0,
//	  "pause_task_requests_timed_out_percentage": 0
//	}
//
// A 0 on a threshold there is an instruction to NEVER PAUSE. Read with `if n > 0` it becomes "unset",
// the default 15 applies, and the crawl pauses at exactly the point the operator disabled it — the
// worst of the available answers, because the report then names a stop the operator chose not to
// have. So every field here is a POINTER, which is what makes "0" and "not mentioned" different
// values. This is the same trap burpsy-react-ui-qzzy found on the eight crawl bounds, and the same
// fix; the two are kept separate because the bounds are counts of work and these are policy about
// failure, and a reader should not have to hold both in one shape to see why.
//
// A threshold of 0 is DISARMED. That is the correct reading for all three: a pause threshold of zero
// failures is a threshold no request can cross.

// ErrorHandling is the resolved error-handling policy for one crawl. See the package comment for why
// every field is a pointer.
type ErrorHandling struct {
	// PauseOnTimeoutCount pauses the crawl after this many CONSECUTIVE timed-out requests. Burp's
	// shipped default is 15 (CrawlDefaults.json).
	PauseOnTimeoutCount *int
	// PauseOnTimeoutPercent pauses the crawl after this PERCENTAGE of its requests have timed out.
	// Burp ships it at 0, so this axis is off unless an operator sets it — a second reason a zero
	// here cannot be read as "unset", since the default is itself zero.
	PauseOnTimeoutPercent *int
	// PauseOnAuthFailures pauses the crawl after this many consecutive authentication failures.
	// Burp's shipped default is 2 and its own settings panel caps the value at 10 (Zrfv.java:109,
	// "Only values between 1 and 10 are allowed"), which is why a value above 10 is refused rather
	// than clamped.
	PauseOnAuthFailures *int
	// FollowUpPasses is how many extra times a request that ended in a transport failure is
	// re-issued through the ordinary perform path. Burp's shipped default is 1, and 0 is a real
	// answer: a crawler that does not retry is a deliberate choice on a target where one is
	// unwelcome, and the flag matters most against a target that rejects unsolicited traffic.
	FollowUpPasses *int
}

// DefaultErrorHandling is what a crawl naming no error-handling key gets.
//
// Every threshold a real value rather than zero, because zero means DISARMED and a default of zero
// across the board would be a crawl that hammers a refusing host forever — the behaviour the family
// exists to prevent. Burp's own shipped defaults are 15, 0, 2 and 1; the percentage is the one that
// ships at 0 and is kept at 0, because that is what Burp does and a default nobody chose should not
// be invented here.
func DefaultErrorHandling() ErrorHandling {
	fifteen, zero, two, one := 15, 0, 2, 1
	return ErrorHandling{
		PauseOnTimeoutCount:   &fifteen,
		PauseOnTimeoutPercent: &zero,
		PauseOnAuthFailures:   &two,
		FollowUpPasses:        &one,
	}
}

// resolved fills the engine defaults in for every key the caller left unset, and leaves a family the
// caller populated exactly as written — INCLUDING one it filled with zeros, meaning never pause.
//
// Resolved ONCE in New rather than at each read, so the pass that trips a threshold and the report
// that names it see the same numbers.
func (e ErrorHandling) resolved() ErrorHandling {
	out := e
	d := DefaultErrorHandling()
	if out.PauseOnTimeoutCount == nil {
		out.PauseOnTimeoutCount = d.PauseOnTimeoutCount
	}
	if out.PauseOnTimeoutPercent == nil {
		out.PauseOnTimeoutPercent = d.PauseOnTimeoutPercent
	}
	if out.PauseOnAuthFailures == nil {
		out.PauseOnAuthFailures = d.PauseOnAuthFailures
	}
	if out.FollowUpPasses == nil {
		out.FollowUpPasses = d.FollowUpPasses
	}
	return out
}

// PauseConfigured reports whether any pause threshold is armed. A family with every threshold at 0 is
// a crawl that NEVER pauses, and that is a state a report has to be able to say out loud rather than
// infer from the absence of a stop.
func (e ErrorHandling) PauseConfigured() bool {
	return armed(e.PauseOnTimeoutCount) || armed(e.PauseOnTimeoutPercent) || armed(e.PauseOnAuthFailures)
}

// followUpPasses is how many extra passes to run, with 0 meaning none.
func (e ErrorHandling) followUpPasses() int {
	if e.FollowUpPasses == nil {
		return 0
	}
	return *e.FollowUpPasses
}

func (e ErrorHandling) timeoutCount() int {
	if e.PauseOnTimeoutCount == nil {
		return 0
	}
	return *e.PauseOnTimeoutCount
}

func (e ErrorHandling) timeoutPercent() int {
	if e.PauseOnTimeoutPercent == nil {
		return 0
	}
	return *e.PauseOnTimeoutPercent
}

func (e ErrorHandling) authFailures() int {
	if e.PauseOnAuthFailures == nil {
		return 0
	}
	return *e.PauseOnAuthFailures
}

// armed reads a threshold as armed-or-not. This is where the pointer earns its keep: without one, a
// 0 the operator wrote and a key the file never mentioned are the same int and nothing can tell them
// apart.
func armed(v *int) bool { return v != nil && *v > 0 }

// errorHandlingKeyRows are the four `crawler/error_handling/*` keys, registered onto the same table
// the crawl_limits rows live in rather than kept separate — so one loader, one report, and one
// place where a key that is neither applied nor reported can be noticed.
func init() {
	for _, r := range []burpCrawlConfigKey{
		{burpKey: "crawler/error_handling/pause_task_requests_timed_out_count", errorField: "PauseOnTimeoutCount"},
		{burpKey: "crawler/error_handling/pause_task_requests_timed_out_percentage", errorField: "PauseOnTimeoutPercent"},
		{burpKey: "crawler/error_handling/consecutive_authentication_failures_before_pausing_task", errorField: "PauseOnAuthFailures"},
		{burpKey: "crawler/error_handling/number_of_follow_up_passes", errorField: "FollowUpPasses"},
	} {
		registerBurpCrawlKey(r)
	}
}

// applyErrorKey decodes one `crawler/error_handling/*` value onto the block.
//
// Separate from applyCrawlKey because the ZERO travels through as a zero rather than being read as
// an absence, and that one difference is the reason this family can express "never pause" at all.
func (c *CrawlConfig) applyErrorKey(row burpCrawlConfigKey, raw json.RawMessage) error {
	n, err := burpCrawlConfigNumber(raw)
	if err != nil {
		return fmt.Errorf("burp crawl configuration: %s: %w", row.burpKey, err)
	}
	if n < 0 {
		return fmt.Errorf("burp crawl configuration: %s: %d is negative; a threshold counts failures "+
			"BEFORE a pause, and a negative one would pause before the first request", row.burpKey, n)
	}
	// Burp's own panel caps this at 10 (Zrfv.java:109). Refused rather than clamped: the cap is the
	// operator's statement about what they meant, and a silent clamp answers a question nobody asked.
	if row.errorField == "PauseOnAuthFailures" && n > 10 {
		return fmt.Errorf("burp crawl configuration: %s: %d is above the maximum of 10 Burp's own "+
			"settings panel allows (Zrfv.java:109); refused rather than clamped, because a clamp "+
			"answers a question nobody asked", row.burpKey, n)
	}
	v := int(n)
	switch row.errorField {
	case "PauseOnTimeoutCount":
		c.ErrorHandling.PauseOnTimeoutCount = &v
	case "PauseOnTimeoutPercent":
		c.ErrorHandling.PauseOnTimeoutPercent = &v
	case "PauseOnAuthFailures":
		c.ErrorHandling.PauseOnAuthFailures = &v
	case "FollowUpPasses":
		c.ErrorHandling.FollowUpPasses = &v
	default:
		return fmt.Errorf("burp crawl configuration: %s names an unknown error_handling field %q",
			row.burpKey, row.errorField)
	}
	return nil
}
