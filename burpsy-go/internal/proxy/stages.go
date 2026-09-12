package proxy

// messageStages carries one message's earlier stages from where they are observable to where the
// exchange is recorded (burpsy-react-ui-c05, under epic mrjw).
//
// # What it is for
//
// burpsy stored one version of each message: the bytes that travelled. Burp's Proxy history shows
// three — Original (what the client sent), Auto-modified (what burpsy's own rules made of it) and
// Edited (what a manual intercept edit made of that, which is what went out) — and the radio that
// picks between them is how an operator answers "what did that Match & Replace rule actually do to
// live traffic", a question this tool could not answer at all. Its substitute was
// Counters.ModifiedUnrecorded: a number saying "traffic was rewritten and you cannot see it".
//
// # Why a carrier rather than parameters
//
// The transformations happen in handleHTTP/handleTunnel, near the top of each path, and the exchange
// is recorded in completeResponse/handleTLSResponse, near the bottom. Threading two more []byte
// parameters through every function between them would put two arguments on signatures that have no
// other business knowing about history — and the WebSocket paths, which record a handshake the
// moment the 101 arrives, would need them too. One value carried alongside the request bytes says
// the same thing at each site.
//
// # What it deliberately does not do
//
// It does not decide whether a stage is worth keeping. It is populated at the two points where the
// stage boundaries are, and the single storage seam (scanner.Capture.storeStages) drops any stage
// byte-identical to the one after it. That split is deliberate: the boundary is a proxy fact and the
// retention rule is a storage fact, and the retention rule has to live where the reading side can be
// checked against it — see core.Exchange.VariantFor, which walks the same rule backwards.
type messageStages struct {
	// original is stage 0: the bytes as the peer sent them, after protocol normalisation only.
	//
	// Normalisation is excluded deliberately. toOriginForm rewrites an absolute-form request line
	// to origin-form because a proxy's client sends the former and an origin requires the latter
	// (RFC 9112 §3.2.1–2) — that is a correction of the tool's own protocol handling, not a
	// modification of the operator's message, and every stage boundary below is taken after it. If
	// normalisation counted as a modification then every proxied request would read as "modified"
	// and the three views would be worthless on exactly the traffic they exist for.
	original []byte
	// auto is stage 1: the bytes after the automatic rules and before any manual edit. Nil means
	// "no second boundary was reached", which the storage seam reads as "stage 1 equals the final
	// bytes" — the state an exchange with no automatic rule and no manual edit is in, and the state
	// that costs no extra bytes.
	//
	// Both fields are populated at their boundaries *unconditionally*, rather than only when a
	// transformation fires. Gating the capture on "did Match & Replace run" would lose the stages of
	// an exchange whose only change was the operator's own edit, because that edit happens after
	// this boundary and would leave nothing to compare the final bytes against.
	auto []byte
}
