import { useState } from "react";
import { Globe } from "lucide-react";
import { api, json, relativeTime } from "../lib/api";
import { useInvalidate } from "../lib/data";
import { useSessionPrompts } from "../lib/data.policy";
import type { SessionPromptResolveRequest, SessionPromptResolveResponse } from "../lib/types.policy";
import { Button, Modal } from "../ui/primitives";

/**
 * The browser-recovery prompt modal (burpsy-react-ui-dq1g) — burpsy's counterpart of Burp's
 * "prompt the user for in-browser session recovery".
 *
 * Burp opens a browser window on the failing response so the operator can log in by hand. burpsy
 * has no window it can open — the console is a page the operator opens themselves — so the prompt
 * is this modal, and the task that hit the action is suspended on the server until the operator
 * answers. The session the operator establishes reaches the retried request the same way Burp's
 * does: through the proxy, into the cookie jar, out on the Cookie header.
 *
 * # Why this layer is mounted globally, not on the Session page
 *
 * The prompt can fire while the operator is anywhere in the console — it is a task that is
 * waiting, not a page they are looking at. A modal rendered only on the Session page would be a
 * prompt the operator cannot see, which is the one failure mode worse than no prompt at all.
 *
 * # Why the list is always subscribed
 *
 * The query is read here, on every page, so a "session" event refetches it and the modal appears
 * and dismisses without a poll. An empty list renders nothing; the cost of that is one small GET
 * per prompt event, which is nothing next to the event stream that already drives the console.
 */
export function SessionPromptLayer(): JSX.Element | null {
 const prompts = useSessionPrompts();
 const invalidate = useInvalidate();
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState("");
 const prompt = prompts.data?.prompts[0] ?? null;

 if (!prompt) return null;

 const resolve = (recovered: boolean) => {
  setBusy(true);
  setError("");
  // The resolve route is riskCredential — resolving a prompt makes burpsy replay the stored
  // login on the operator's behalf — so it sits behind the confirm gate and a bare POST is
  // refused 428. Minting the token HERE, in the click handler, is the honest shape: the
  // operator's click IS the confirmation, the mint is one POST the console makes on the
  // operator's behalf at the moment of the click, and the 60-second TTL is spent within the
  // same interaction. (The earlier version of this page sent no token at all: every answer came
  // back 428, the modal never dismissed, and a suspended task could never be recovered from
  // the console — a prompt nobody can answer is the failure this bead exists to close.)
  //
  // The mint path is the GATE'S, not this page's: a confirmation is issued against the route
  // pattern and spent against that same pattern, so it is minted at the pattern's own
  // /confirm endpoint with no prompt id in it. A per-prompt mint path would be a second naming
  // scheme for one authorisation decision, and a token minted "for prompt 3" says something
  // the gate cannot enforce — the token authorises the route, and the gate binds it there.
  //
  // api() does that mint (burpsy-react-ui-p1uz): it resolves this URL to the gated pattern and mints
  // at that pattern's /confirm, exactly as described above.
  void api<SessionPromptResolveResponse>(
   `/api/session/prompts/${prompt.id}/resolve`,
   json("POST", { recovered } satisfies SessionPromptResolveRequest),
  )
   .then(() => {
    // The server notifies on resolve; the invalidation is the local half of the same signal.
    void invalidate([["session"]]);
   })
   .catch((failure: unknown) => {
    // A stale modal (the prompt timed out, or was already answered) reports the refusal
    // rather than pretending the answer landed.
    setError(failure instanceof Error ? failure.message : "Could not resolve the prompt");
    void invalidate([["session"]]);
   })
   .finally(() => setBusy(false));
 };

 return (
  <Modal
   open
   // Closing the modal is a decline: the operator is saying "stop waiting", which — like the
   // Decline button — means the request is not sent. The modal reappears on the next prompt
   // event if the task is still suspended.
   onOpenChange={(open) => {
    if (!open) resolve(false);
   }}
   title="Session recovery needed"
   description={`The rule “${prompt.rule_name}” is suspended: the session for ${prompt.request_url} is not valid, and the rule asks for it to be recovered by hand.`}
  >
   <div className="stack">
    <p>
     <Globe size={14} /> Log in to the application in your browser — the one whose traffic burpsy proxies — then confirm below. The
     suspended task resumes and the request goes out with the session your browser established.
    </p>
    <p className="field-hint">
     The task has been waiting {relativeTime(new Date(prompt.created_at).getTime())}. If you cannot recover the session, decline: the
     request is not sent, and the rule's trace says the prompt was declined rather than reporting a session that was never established.
    </p>
    {error ? <p className="field-hint">{error}</p> : null}
    <div className="inline-add">
     <Button onClick={() => resolve(true)} disabled={busy}>
      I&apos;ve recovered the session
     </Button>
     <Button variant="outline" onClick={() => resolve(false)} disabled={busy}>
      Decline — don&apos;t send the request
     </Button>
    </div>
   </div>
  </Modal>
 );
}
