import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { Button, ErrorNotice, Modal, Textarea } from "./primitives";

/**
 * burpsy Clickbandit (burpsy-react-ui-g67w): Burp's top-level "Burp Clickbandit". The script is
 * pasted into the developer console of the page under test; it records clicks and builds a
 * clickjacking proof of concept the operator can review and save as HTML.
 */
export function ClickbanditDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  const { data, error, refetch } = useQuery({
    queryKey: ["clickbandit-script"],
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/engagement/clickbandit.js", { signal });
      if (!response.ok) throw new Error(`the script could not be loaded (${response.status})`);
      return response.text();
    },
    enabled: open,
    staleTime: Infinity,
  });
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Clickbandit" description="Turn a clickjacking finding into a recorded, replayable proof of concept." wide>
      <ol className="stack-tight" style={{ paddingLeft: "1.2rem" }}>
        <li>Copy the script below.</li>
        <li>In your browser, open the page to test and its developer console, paste the script and press Enter.</li>
        <li>Click Start, click through the page as the victim would, then click Finish.</li>
        <li>Review the overlay: Toggle transparency, Reset, + and − to zoom, arrow keys to nudge. Save writes the proof of concept as an HTML file.</li>
      </ol>
      <p className="field-hint">
        Disable click actions stops the page acting on your clicks while they are recorded; Sandbox iframe frames the page with
        the sandbox attribute, which defeats many frame busters. A page whose JavaScript is untrusted can tamper with what is
        recorded, and so with the HTML that is saved.
      </p>
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      <Textarea aria-label="Clickbandit script" readOnly rows={8} value={data ?? ""} style={{ fontFamily: "var(--font-mono)" }} />
      <div className="detail-actions">
        <Button
          disabled={!data}
          onClick={() =>
            void copyToClipboard(data ?? "").then(
              () => toast.success("Clickbandit copied — paste it into the target page's developer console"),
              () => toast.error("The script could not be copied; select it in the box and copy it by hand"),
            )
          }
        >
          Copy Clickbandit to clipboard
        </Button>
      </div>
    </Modal>
  );
}
