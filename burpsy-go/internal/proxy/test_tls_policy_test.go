package proxy

// permissiveTLS is the upstream-TLS policy a test that drives a SELF-SIGNED origin needs.
//
// It exists as a named helper rather than as WithUpstreamTLS(NewTLSPolicy().WithVerify(false)) at
// every call site because the change it accompanies is the point: the proxy's interception leg used to
// open with verification unconditionally off, and a test that reaches a self-signed origin now has to
// SAY that it is doing so. A test that silently relied on the old unconditional skip was asserting
// against a behaviour that no longer exists, and the failures said so — the fix is to declare the
// policy, not to weaken it again (burpsy-react-ui-f365).
//
// Tests about verification itself do NOT use this: tls_policy_test.go drives real certificates
// through the default policy precisely because that is the behaviour under test.
func permissiveTLS() *TLSPolicy {
	return NewTLSPolicy().WithVerify(false)
}
