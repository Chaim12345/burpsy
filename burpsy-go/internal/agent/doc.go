// Package agent is the supervised agent runner: a task the operator hands over, a sequence of
// proposed steps each carrying the risk class of the route it maps to, per-step approval for anything
// the policy will not run unattended, and a transcript of every proposal, decision and result.
//
// The package is a library. It imports nothing from the console (internal/web) or the MCP transport:
// the console's route manifest, confirmation gate and LLM client reach it through the small
// interfaces in run.go (Classifier, Invoker, Approver, Planner), so the enforcement stays where it
// is - the console's gate - and this package only decides when to ask a human. A step the policy
// lets through that the console still refuses with 428 is escalated to the Approver, never retried
// without a token.
package agent
