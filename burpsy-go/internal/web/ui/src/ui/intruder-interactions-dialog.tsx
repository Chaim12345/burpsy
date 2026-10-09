// The interaction details behind one Intruder row's "Interactions" count (burpsy-react-ui-nib6):
// Burp shows them in a panel for the selected result; burpsy opens them in a dialog from the cell.

import { useState } from "react";
import { useCollaboratorInteraction, type CollaboratorInteractionRow } from "../lib/data.collab";
import { Button, Modal } from "./primitives";
import { LoadingPanel } from "./layout";
import { SimpleTable } from "./table";

export function IntruderInteractionsDialog({
  ordinal,
  addresses,
  rows,
  onClose,
}: {
  ordinal: number | null;
  addresses: string[];
  rows: CollaboratorInteractionRow[];
  onClose: () => void;
}): JSX.Element {
  const [selected, setSelected] = useState<number | null>(null);
  return (
    <Modal
      open={ordinal !== null}
      onOpenChange={(open) => {
        if (!open) {
          setSelected(null);
          onClose();
        }
      }}
      title={`Collaborator interactions — attempt ${ordinal ?? ""}`}
      description={`Callbacks carrying ${addresses.join(", ") || "this attempt's address"}.`}
      wide
    >
      {rows.length ? (
        <SimpleTable headers={["#", "Type", "Client IP", "Time", "Query", "Request"]}>
          {rows.map((row) => (
            <tr key={row.id}>
              <td className="cell-num">{row.id}</td>
              <td>{row.type.toUpperCase()}</td>
              <td className="mono">{row.client_ip}</td>
              <td className="cell-num">{new Date(row.at_ms).toLocaleTimeString()}</td>
              <td>{row.q_type ?? "—"}</td>
              <td>
                <Button variant="outline" size="small" onClick={() => setSelected(row.id === selected ? null : row.id)}>
                  {row.id === selected ? "Hide" : "Details"}
                </Button>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : (
        <p className="cell-dim">No callback has carried this attempt's address yet. The count updates as interactions arrive.</p>
      )}
      {selected !== null ? <InteractionBytes id={selected} /> : null}
    </Modal>
  );
}

function InteractionBytes({ id }: { id: number }): JSX.Element {
  const detail = useCollaboratorInteraction(id);
  if (detail.isLoading || !detail.data) return <LoadingPanel label="Loading interaction" />;
  const d = detail.data;
  return (
    <div>
      <p className="field-hint">
        Correlation ID {d.correlation_id} · client IP {d.client_ip} ({d.client_ip_means})
      </p>
      {d.raw_request ? (
        <pre className="mono" style={{ whiteSpace: "pre-wrap", maxHeight: "16rem", overflow: "auto" }}>
          {d.raw_request}
        </pre>
      ) : (
        <p className="cell-dim">No request body — DNS interactions carry a query, not a request.{d.q_type ? ` Query type: ${d.q_type}.` : ""}</p>
      )}
    </div>
  );
}
