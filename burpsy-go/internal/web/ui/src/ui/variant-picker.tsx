import { Button } from "./primitives";

/**
 * Burp's three readings of a message in history (burpsy-react-ui-c05, under epic mrjw).
 *
 * "Edited" is the message as it went on the wire — the request after the operator's own intercept
 * edit, the response after theirs — and it is the default because it is what the traffic actually
 * was. "Original" is what the peer sent. "Auto-modified" is what burpsy's own Match & Replace rules
 * made of it before any manual edit; with no manual edit it is the same bytes as Edited, so it is
 * never offered as a separate reading.
 *
 * A union rather than loose `{id, label}` pairs, because the union is what the API's resolved ids
 * and this control have to agree on: a caller able to name a reading the server has no id for could
 * only render a pane that lies about which bytes it is showing.
 *
 * The helpers below each take *one direction's* ids rather than the whole `variants` object, so a
 * caller cannot pass the response's readings to the request's pane — the type makes the mix-up a
 * compile error rather than a viewer showing two different messages under one label.
 */
export type MessageVariant = "original" | "auto-modified" | "edited";

/** Burp's own labels. Its settings panel lists them Original / Edited / Auto-modified. */
const LABELS: Record<MessageVariant, string> = {
 original: "Original",
 "auto-modified": "Auto-modified",
 edited: "Edited",
};

/**
 * The readings one direction of a row can actually show, in Burp's order.
 *
 * "Edited" is always present and always last: it is the bytes that travelled, so it is the one
 * reading every exchange has. An earlier reading appears only when the server resolved an id for it
 * — which makes this a list of *available comparisons* rather than of capabilities. A row nothing
 * modified yields exactly one entry, and VariantPicker then renders nothing at all.
 */
export function availableVariants(original: number | null | undefined, autoModified: number | null | undefined): MessageVariant[] {
 const out: MessageVariant[] = [];
 if (original != null) out.push("original");
 if (autoModified != null) out.push("auto-modified");
 out.push("edited");
 return out;
}

/**
 * The message id to fetch for one reading of one direction.
 *
 * The fallback to `edited` is the whole reason the server sends nulls rather than three ids: null
 * means "this reading is the bytes that travelled", and the caller resolves that to the id it
 * already has. A pane therefore always has bytes to show — no reading ever renders an empty viewer,
 * and no fetcher is ever called with null.
 */
export function variantMessageId(
 edited: number | null,
 original: number | null | undefined,
 autoModified: number | null | undefined,
 variant: MessageVariant,
): number | null {
 if (variant === "edited") return edited;
 if (variant === "original") return original ?? edited;
 return autoModified ?? edited;
}

/**
 * The reading picker: a small segmented control, rendered only when there is a comparison to make.
 *
 * Returning null for a single reading is the point rather than an optimisation. Almost every row in
 * a capture is modified by nothing, and a control that appeared on all of them — offering three
 * readings that all show the same bytes — would be both noise and a mild lie about what the row
 * contains. So the control's presence is itself the signal that this exchange was rewritten, which
 * is the same fact the History "Edited" column carries in a form you can scan down.
 */
export function VariantPicker({
 value,
 options,
 onChange,
 label,
}: {
 value: MessageVariant;
 options: MessageVariant[];
 onChange: (next: MessageVariant) => void;
 /** Distinguishes the request's picker from the response's for screen readers, since one row can
  *  show two of these and their option sets legitimately differ. */
 label: string;
}): JSX.Element | null {
 if (options.length < 2) return null;
 return (
  <span className="variant-picker" role="radiogroup" aria-label={`${label} message reading`}>
   {options.map((option) => (
    <Button
     key={option}
     size="small"
     variant={option === value ? "primary" : "quiet"}
     role="radio"
     aria-checked={option === value}
     onClick={() => onChange(option)}
    >
     {LABELS[option]}
    </Button>
   ))}
  </span>
 );
}
