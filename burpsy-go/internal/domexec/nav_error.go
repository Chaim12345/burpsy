package domexec

import "strings"

// chromeErrorStatusPage is the net error Chrome reports when a navigation's response is an HTTP error
// status (4xx/5xx) with an empty body: the request reached the server and was answered, but there is
// no document to render. chromedp surfaces it only as text ("page load error net::ERR_..." from
// chromedp.Navigate, or the errorText of page.Navigate), so the classification is by that stable
// Chrome identifier.
const chromeErrorStatusPage = "net::ERR_HTTP_RESPONSE_CODE_FAILURE"

// IsErrorStatusPage reports whether err is a navigation the target answered with an HTTP error status
// and no document (burpsy-react-ui-4kmr).
//
// It is not a failure to reach the target, and a caller must not count it as one: the canonical case
// is a browser loading, by GET, the URL of a request that was audited as a POST, and a framework that
// maps the route to POST alone answering 405 with no body. The page has no DOM to observe, which makes
// a DOM check's result undecided - not a send failure, and not evidence the target is failing.
func IsErrorStatusPage(err error) bool {
	return err != nil && strings.Contains(err.Error(), chromeErrorStatusPage)
}
