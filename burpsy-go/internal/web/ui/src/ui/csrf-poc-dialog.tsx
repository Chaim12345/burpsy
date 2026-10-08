import { useQuery } from "@tanstack/react-query";
import { ExternalLink, FileCode2, RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, copyToClipboard, downloadText } from "../lib/api";
import { useCsrfPoc } from "../lib/csrf-poc";
import { Button, Checkbox, Empty, Field, Modal, Select, Toolbar } from "./primitives";

/**
 * The CSRF PoC generator's dialog (burpsy-react-ui-0z10) — Burp's "Generate CSRF PoC" panel: the
 * generated HTML, the technique choice, the auto-submit option, and "Test in browser"
 * (generate-csrf-poc.html).
 *
 * The PoC used to be opened as a blob URL, which inherits the console's origin — the one surface a
 * generated, attacker-shaped page must never run on. Now the HTML is shown here, and "Test in
 * browser" opens the one-shot URL the server mints on its own port: an origin with no console
 * routes, no console cookies, spent on the first fetch.
 *
 * The technique and auto-submit choices are component state, not workspace state: the dialog
 * component stays mounted (only the Modal opens), so they persist across openings like Burp's
 * Options do, without making every page re-render on a dialog option.
 */

/** Burp's technique choices, with the wording its generator uses. */
const CSRF_TECHNIQUES = [
 { value: "auto", label: "Auto", hint: "the most appropriate technique capable of generating the required request" },
 { value: "form", label: "Form (hidden inputs)", hint: "urlencoded bodies only" },
 { value: "multipart", label: "Multipart form", hint: "multipart bodies; the browser regenerates the boundary" },
 { value: "plain", label: "Plain text form", hint: "JSON/XML bodies with an equals character; the browser sends Content-Type: text/plain" },
 { value: "xhr", label: "Cross-domain XHR", hint: "the exact Content-Type and body; requires CORS" },
] as const;

type CsrfView = {
 technique: string;
 method: string;
 action: string;
 html: string;
 notes: string[];
 test_url?: string;
};

export function CsrfPocDialog(): JSX.Element {
 const exchange = useCsrfPoc((state) => state.exchange);
 const close = useCsrfPoc((state) => state.close);
 const [technique, setTechnique] = useState("auto");
 const [autoSubmit, setAutoSubmit] = useState(true);
 const open = exchange !== null;

 const query = useQuery({
  queryKey: ["csrf-poc", exchange?.id ?? 0, technique, autoSubmit],
  enabled: open && exchange !== null,
  queryFn: () =>
   api<CsrfView>(`/api/exchange/${exchange!.id}/csrf?technique=${technique}&auto_submit=${autoSubmit}`),
 });

 const view = query.data;

 // A one-shot page is minted only when the operator asks to test, never on a refetch: each mint is a
 // page the PoC host holds until it is fetched or expires.
 const testInBrowser = () => {
  if (!exchange) return;
  // Opened synchronously, inside the click, so a popup blocker sees the gesture; pointed at the
  // page once it is minted.
  const tab = window.open("about:blank", "_blank");
  void api<CsrfView>(`/api/exchange/${exchange.id}/csrf?technique=${technique}&auto_submit=${autoSubmit}&test_url=true`).then(
   (minted) => {
    if (!minted.test_url) {
     tab?.close();
     toast.error("No test URL was minted");
     return;
    }
    // The PoC host's own origin — never the console's; see the dialog's doc comment for why that
    // property is the point. The opener is cut so the page cannot reach back into the console.
    if (tab) {
     tab.opener = null;
     tab.location.href = minted.test_url;
    } else {
     window.open(minted.test_url, "_blank", "noopener");
    }
   },
   (failure: unknown) => {
    tab?.close();
    toast.error(failure instanceof Error ? failure.message : "The test page could not be minted");
   },
  );
 };

 return (
  <Modal
   open={open}
   onOpenChange={(next) => {
    if (!next) close();
   }}
   wide
   title="Generate CSRF PoC"
   description="An HTML page that makes a victim's browser replay the captured request. The technique is Burp's choice; the notes say what the browser will actually send."
  >
   <div className="stack">
    <Field label="CSRF technique" hint={CSRF_TECHNIQUES.find((t) => t.value === technique)?.hint}>
     {(id) => (
      <Select id={id} value={technique} onChange={(event) => setTechnique(event.target.value)}>
       {CSRF_TECHNIQUES.map((t) => (
        <option key={t.value} value={t.value}>
         {t.label}
        </option>
       ))}
      </Select>
     )}
    </Field>
    <Checkbox
     checked={autoSubmit}
     label="Include auto-submit script — the request fires when the page loads"
     onCheckedChange={setAutoSubmit}
    />

    {query.error ? <Empty title="Could not generate the PoC" detail={String(query.error)} /> : null}

    {view ? (
     <>
      <Toolbar>
       <Button variant="outline" size="small" onClick={() => void query.refetch()}>
        <RefreshCw size={13} />
        Regenerate
       </Button>
       <Button size="small" onClick={testInBrowser}>
        <ExternalLink size={13} />
        Test in browser
       </Button>
       <Button variant="outline" size="small" onClick={() => void copyToClipboard(view.html).then(() => toast.success("PoC HTML copied"))}>
        <FileCode2 size={13} />
        Copy HTML
       </Button>
       <Button variant="outline" size="small" onClick={() => downloadText("csrf-poc.html", view.html)}>
        Download
       </Button>
      </Toolbar>

      <div className="field">
       <label>
        <span>
         Generated HTML — {view.technique} technique, {view.method} {view.action}
        </span>
       </label>
       <pre className="poc-html">{view.html}</pre>
      </div>

      {view.notes.length > 0 ? (
       <div className="field">
        <label>
         <span>Notes — what the browser will actually send</span>
        </label>
        <ul className="stack-tight poc-notes">
         {view.notes.map((note) => (
          <li key={note}>{note}</li>
         ))}
        </ul>
       </div>
      ) : null}
     </>
    ) : query.isFetching ? (
     <Empty title="Generating…" detail="The PoC is built from the exchange's own bytes" />
    ) : null}
   </div>
  </Modal>
 );
}
