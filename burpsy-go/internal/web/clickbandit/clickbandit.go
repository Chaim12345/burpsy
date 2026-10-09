// Package clickbandit embeds burpsy's Clickbandit script (burpsy-react-ui-g67w), Burp's tool for
// turning a clickjacking finding into a recorded, replayable proof-of-concept overlay. The script is
// burpsy's own, written to the documented workflow (desktop/tools/clickbandit.html).
package clickbandit

import _ "embed"

// Script is the JavaScript the operator pastes into the developer console of the page under test.
//
//go:embed clickbandit.js
var Script string
