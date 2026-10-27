import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
 ruleSchemeFor,
 useDismissPlatformAuthFailure,
 usePlatformAuth,
 usePlatformAuthFailures,
 useSavePlatformAuth,
} from "../lib/data.netauth";
import { Button, Field, Input, Modal, Toolbar } from "./primitives";

/**
 * Burp's "Prompt for credentials on platform authentication failure" (burpsy-react-ui-3xnt). While
 * the setting is on, the most recent failure the server recorded is put to the operator: enter
 * credentials for that host, or dismiss it. The credential applies from the next request on; the
 * request that failed has already returned its 401.
 */
export function PlatformAuthPrompt(): JSX.Element | null {
 const { data: settings } = usePlatformAuth();
 const enabled = settings?.prompt_on_authentication_failure === true;
 const { data } = usePlatformAuthFailures(enabled);
 const save = useSavePlatformAuth();
 const dismiss = useDismissPlatformAuthFailure();
 const failure = enabled ? data?.failures[0] : undefined;

 const [username, setUsername] = useState("");
 const [password, setPassword] = useState("");
 useEffect(() => {
  setUsername("");
  setPassword("");
 }, [failure?.host]);

 if (!failure) return null;
 const scheme = ruleSchemeFor(failure.scheme);
 const reason =
  failure.reason === "rejected"
   ? `refused the credential configured for it (${failure.count} time${failure.count === 1 ? "" : "s"})`
   : `asked for credentials and none are configured for it (${failure.count} time${failure.count === 1 ? "" : "s"})`;

 const submit = (): void => {
  if (!scheme) return;
  save.mutate(
   { host: failure.host, scheme, username: username.trim(), password, realm: failure.realm ?? "" },
   {
    onSuccess: () => toast.success(`Credentials saved for ${failure.host}; they apply from its next request`),
    onError: (cause) => toast.error(cause instanceof Error ? cause.message : "The credentials were not saved"),
   },
  );
 };
 const close = (): void =>
  dismiss.mutate(failure.host, {
   onError: (cause) => toast.error(cause instanceof Error ? cause.message : "Could not dismiss the prompt"),
  });

 return (
  <Modal
   open
   onOpenChange={(open) => {
    if (!open) close();
   }}
   title="Platform authentication failed"
   description={`${failure.host} ${reason}: ${failure.scheme}${failure.realm ? ` in realm "${failure.realm}"` : ""}.`}
  >
   {scheme ? (
    <>
     <Toolbar>
      <Field label="Username" hint={scheme === "ntlmv2" ? "DOMAIN\\user for NTLM" : undefined}>
       {(id) => <Input id={id} value={username} autoComplete="off" onChange={(event) => setUsername(event.target.value)} />}
      </Field>
      <Field label="Password">
       {(id) => (
        <Input
         id={id}
         type="password"
         value={password}
         autoComplete="off"
         onChange={(event) => setPassword(event.target.value)}
         onKeyDown={(event) => {
          if (event.key === "Enter" && username.trim()) submit();
         }}
        />
       )}
      </Field>
     </Toolbar>
     <p className="field-hint">Saved as a platform-authentication rule for {failure.host}. The request that failed is not resent.</p>
     <Toolbar>
      <Button onClick={submit} disabled={!username.trim() || save.isPending}>
       Save credentials
      </Button>
      <Button variant="outline" onClick={close}>
       Dismiss
      </Button>
     </Toolbar>
    </>
   ) : (
    <>
     <p className="field-hint">This build cannot answer a {failure.scheme} challenge, so there is nothing to enter here.</p>
     <Toolbar>
      <Button variant="outline" onClick={close}>
       Dismiss
      </Button>
     </Toolbar>
    </>
   )}
  </Modal>
 );
}
