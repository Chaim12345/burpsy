import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "../lib/api";
import {
  useClientCerts,
  useDeleteClientCert,
  useDeletePlatformAuth,
  usePlatformAuth,
  useSaveClientCert,
  useSavePlatformAuth,
} from "../lib/data.netauth";
import { LoadingPanel, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Select, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/**
 * Settings → Network: platform authentication and client TLS certificates.
 *
 * In its own file rather than appended to settings.tsx so that concurrent work on that page
 * and on this surface cannot collide over the same lines. settings.tsx gains an import and
 * two elements, and nothing else about it moves.
 *
 * # What the panels say out loud
 *
 * Three things, each of which would otherwise be an absence the operator has to interpret:
 *
 *   - NTLM and Negotiate are not implemented, and the panel says so instead of offering a
 *     selector that quietly omits them. A scheme option that configures nothing is worse
 *     than no option: the rule looks saved and the requests go out unauthenticated.
 *   - PKCS#11 hardware tokens are out of scope, stated the same way and for the same reason.
 *   - Whether the rules are actually presented on egress. A store the API can write to and a
 *     sender that was never given it is a rule on the panel that no request carries, so the
 *     server reports which it is and the panel repeats it.
 */

/** Renders a mutation failure as its server-side message, which names what to fix. */
function failureText(failure: unknown, fallback: string): string {
  if (failure instanceof ApiError) return failure.message;
  if (failure instanceof Error) return failure.message;
  return fallback;
}

export function PlatformAuthSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = usePlatformAuth();
  const save = useSavePlatformAuth();
  const remove = useDeletePlatformAuth();

  const [host, setHost] = useState("");
  const [scheme, setScheme] = useState("basic");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [realm, setRealm] = useState("");

  const schemes = data?.schemes ?? [];
  const canAdd = host.trim() !== "" && username.trim() !== "" && !save.isPending;

  const add = (): void => {
    save.mutate(
      { host: host.trim(), scheme, username: username.trim(), password, realm: realm.trim() },
      {
        onSuccess: (result) => {
          toast.success(result.replaced ? `Updated ${result.rule.host}` : `Added ${result.rule.host}`);
          // The password is cleared and the host kept: the next thing an operator does is
          // usually add a second scheme for the same host, and a secret left in a form field
          // is a secret on screen for longer than it needs to be.
          setPassword("");
        },
        onError: (failure) => toast.error(failureText(failure, "The rule was not saved")),
      },
    );
  };

  return (
    <Card>
      <SectionHeading
        title="Platform authentication"
        detail="Credentials burpsy presents to a host that demands them. Rules are matched top to bottom and the first host match wins. Presented on Repeater sends, scanner probes and browser traffic through the proxy — a browser's own Authorization header is never replaced. Digest needs the host's 401 challenge first, so the first request to a protected host is refused and the next one authenticates."
        actions={
          <>
            {data ? (
              <Badge tone={data.presented_on_egress ? "good" : "warn"}>
                {data.presented_on_egress ? "presented on egress" : "not presented"}
              </Badge>
            ) : null}
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading platform authentication" /> : null}

      {data && !data.presented_on_egress ? (
        <div className="notice">
          <span>
            These rules are stored but this build&apos;s sender was not given them, so nothing presents them. A rule
            here will not authenticate anything until that is wired.
          </span>
        </div>
      ) : null}

      {data && data.unsupported.length ? (
        <div className="notice">
          <span>
            {data.unsupported.join(", ")} {data.unsupported.length === 1 ? "is" : "are"} not implemented by this build
            and cannot be selected. NTLMv1 is DES-only — a weaker credential that also does not work — and Negotiate
            needs a Kerberos credential rather than a password. Basic is sent preemptively; Digest and NTLMv2 answer
            one challenge first, with NTLMv2 exchanging NTLMSSP negotiate, challenge and authenticate messages.
          </span>
        </div>
      ) : null}

      <Toolbar>
        <Field label="Host pattern" hint="For example api.example.com or *.example.com.">
          {(id) => (
            <Input id={id} value={host} placeholder="api.example.com" onChange={(event) => setHost(event.target.value)} />
          )}
        </Field>
        <Field label="Scheme" hint="Basic is preemptive; Digest and NTLMv2 wait for a challenge.">
          {(id) => (
            <Select
              id={id}
              value={scheme}
              onChange={(event) => setScheme(event.target.value)}
              style={{ maxWidth: "var(--w-sm)" }}
            >
              {schemes.map((option) => (
                <option key={option} value={option}>
                  {option === "basic" ? "Basic" : option === "digest" ? "Digest" : option === "ntlmv2" ? "NTLMv2" : option}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Username">
          {(id) => <Input id={id} value={username} onChange={(event) => setUsername(event.target.value)} />}
        </Field>
        <Field label="Password" hint="Stored, never served back. An empty password is allowed.">
          {(id) => (
            <Input
              id={id}
              type="password"
              value={password}
              autoComplete="off"
              onChange={(event) => setPassword(event.target.value)}
            />
          )}
        </Field>
        <Field label="Realm" hint="Digest only. Empty means any realm the host challenges with.">
          {(id) => (
            <Input
              id={id}
              value={realm}
              placeholder="any realm"
              onChange={(event) => setRealm(event.target.value)}
              disabled={scheme !== "digest"}
            />
          )}
        </Field>
        <Button disabled={!canAdd} onClick={add}>
          <Plus size={13} />
          Add rule
        </Button>
      </Toolbar>

      {data && data.empty ? (
        <Empty
          title="No platform-authentication rules"
          detail="Nothing is sent an Authorization header on burpsy's own initiative. Add a rule for a host behind HTTP authentication."
        />
      ) : null}
      {data && !data.empty ? (
        <SimpleTable headers={["Host pattern", "Scheme", "Username", "Realm", "Password", ""]}>
          {data.rules.map((rule) => (
            <tr key={`${rule.host}-${rule.scheme}`}>
              <td>
                <code>{rule.host}</code>
              </td>
              <td>
                <Badge tone="neutral">{rule.scheme}</Badge>
              </td>
              <td>{rule.username}</td>
              <td>{rule.realm ? <code>{rule.realm}</code> : <span className="field-hint">any</span>}</td>
              <td>
                {/* Presence, never length: a length is a brute-force hint, and a blank cell
                    would read as "no credential configured" for a rule that is live. */}
                <Badge tone={rule.has_password ? "good" : "warn"}>{rule.has_password ? "stored" : "empty"}</Badge>
              </td>
              <td>
                <IconButton
                  label={`Remove the ${rule.scheme} rule for ${rule.host}`}
                  size="small"
                  disabled={remove.isPending}
                  onClick={() =>
                    remove.mutate(
                      { host: rule.host, scheme: rule.scheme },
                      {
                        onSuccess: () => toast.success(`Removed ${rule.scheme} for ${rule.host}`),
                        onError: (failure) => toast.error(failureText(failure, "The rule was not removed")),
                      },
                    )
                  }
                >
                  <Trash2 size={13} />
                </IconButton>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
    </Card>
  );
}

export function ClientCertificatesSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useClientCerts();
  const save = useSaveClientCert();
  const remove = useDeleteClientCert();

  const [host, setHost] = useState("");
  const [path, setPath] = useState("");
  const [passphrase, setPassphrase] = useState("");

  const canAdd = host.trim() !== "" && path.trim() !== "" && !save.isPending;

  const add = (): void => {
    save.mutate(
      { host: host.trim(), path: path.trim(), passphrase },
      {
        onSuccess: (result) => {
          toast.success(result.replaced ? `Rebound ${result.binding.host}` : `Bound ${result.binding.host}`);
          setPassphrase("");
        },
        // The server reads and decrypts the file during the POST, so this message names which
        // of four things to change — a missing file, a rejected passphrase, a file that is not
        // PKCS#12, or one carrying no key pair.
        onError: (failure) => toast.error(failureText(failure, "The certificate was not bound")),
      },
    );
  };

  return (
    <Card>
      <SectionHeading
        title="Client TLS certificates"
        detail="PKCS#12 identities presented when a host asks for a client certificate, on the proxy's upstream leg and on every egress."
        actions={
          <>
            {data ? (
              <Badge tone={data.presented_on_egress ? "good" : "warn"}>
                {data.presented_on_egress ? "presented on egress" : "not presented"}
              </Badge>
            ) : null}
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading client certificates" /> : null}

      {data && !data.pkcs11_supported ? (
        <div className="notice">
          <span>
            PKCS#11 hardware tokens are not supported by this build — only PKCS#12 files (.p12 or .pfx). A token needs
            a vendor driver this binary does not link, and the signing has to happen inside the token, so it is stated
            here rather than offered as an option that cannot open one. The file is read and decrypted when you bind
            it, so a wrong passphrase is reported now rather than as a failed handshake later.
          </span>
        </div>
      ) : null}

      {/* One notice per failure rather than a list inside one: `.notice` is a flex row, so a
          nested <ul> would sit beside the summary text instead of under it, and a <ul> inside
          the <span> would not be valid markup. Each stale binding is one sentence naming the
          host and the reason, which is the whole content anyway. */}
      {data?.restore_failures.map((failure) => (
        <div className="notice notice-warn" key={failure}>
          <span>Not presented, and it was configured: {failure}</span>
        </div>
      ))}

      <Toolbar>
        <Field label="Host pattern" hint="For example api.example.com or *.example.com.">
          {(id) => (
            <Input id={id} value={host} placeholder="api.example.com" onChange={(event) => setHost(event.target.value)} />
          )}
        </Field>
        <Field label="PKCS#12 file" hint="A path on the machine running burpsy, not an upload.">
          {(id) => (
            <Input id={id} value={path} placeholder="/path/to/identity.p12" onChange={(event) => setPath(event.target.value)} />
          )}
        </Field>
        <Field label="Passphrase" hint="Stored, never served back. Leave empty for a passwordless file.">
          {(id) => (
            <Input
              id={id}
              type="password"
              value={passphrase}
              autoComplete="off"
              onChange={(event) => setPassphrase(event.target.value)}
            />
          )}
        </Field>
        <Button disabled={!canAdd} onClick={add}>
          <Plus size={13} />
          Bind certificate
        </Button>
      </Toolbar>

      {data && data.empty ? (
        <Empty
          title="No client certificates bound"
          detail="No handshake carries a client identity. Bind a PKCS#12 file to reach an app that requires TLS client authentication without putting it on the passthrough list."
        />
      ) : null}
      {data && !data.empty ? (
        <SimpleTable headers={["Host pattern", "Subject", "Issuer", "Expires", "Fingerprint", "File", ""]}>
          {data.bindings.map((binding) => (
            <tr key={binding.host}>
              <td>
                <code>{binding.host}</code>
              </td>
              <td>{binding.subject}</td>
              <td>{binding.issuer}</td>
              <td>{binding.not_after}</td>
              <td>
                {/* Truncated for the row, full in the title: the value an operator compares
                    against a server log is 64 hex characters, which no 24px row can hold. */}
                <code title={binding.fingerprint}>{binding.fingerprint.slice(0, 16)}…</code>
              </td>
              <td>
                <code title={binding.path}>{binding.path}</code>
              </td>
              <td>
                <IconButton
                  label={`Remove the client certificate bound to ${binding.host}`}
                  size="small"
                  disabled={remove.isPending}
                  onClick={() =>
                    remove.mutate(binding.host, {
                      onSuccess: () => toast.success(`Removed the certificate for ${binding.host}`),
                      onError: (failure) => toast.error(failureText(failure, "The binding was not removed")),
                    })
                  }
                >
                  <Trash2 size={13} />
                </IconButton>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
    </Card>
  );
}
