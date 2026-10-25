import { ExternalLink } from "lucide-react";
import type { Advisory, AdvisoryLink } from "../lib/types";

/**
 * The issue-definition catalogue's reader, shared by everything that renders one.
 *
 * The catalogue is 183 entries of long-form description, remediation and taxonomy — the thing that
 * turns a one-line check name into something an operator can act on and put in front of a client.
 * Two screens show it: a finding's advisory on the Issues tab (joined to what was found) and the
 * browsable catalogue under Target (independent of whether anything was found). This component lives
 * in `ui/` rather than in either page because two renderers of one shape drift — the same argument
 * events.go makes for carrying change kinds instead of rows.
 *
 * Prose arrives pre-split into plain-text paragraphs, so there is no markup to trust here. Links are
 * separate typed fields, rendered as real anchors from data rather than parsed out of a string.
 */
export function AdvisoryReader({
 advisory,
 note,
 heading,
}: {
 advisory?: Advisory | null;
 /** Why there is no advisory, for the checks that deliberately have none. */
 note?: string;
 /**
  * The h3 above the description. Left unset, it names the definition — which is what the Issues tab
  * needs, because the pane above it is titled with the *finding* rather than with the issue class.
  * A screen whose own heading already names the definition passes "Description" instead, so the
  * name is not said twice on one page.
  */
 heading?: string;
}): JSX.Element | null {
 if (!advisory) {
  // A deliberate absence is stated. "No catalogue entry, and here is why" and "nothing looked" are
  // different claims, and a blank panel reads as a loading failure.
  return note ? (
   <div>
    <h3>{heading ?? "Issue definition"}</h3>
    <p className="prose cell-dim">{note}</p>
   </div>
  ) : null;
 }
 return (
  <div className="advisory-catalogue">
   <h3>
    {heading ?? (
     <>
      Issue definition — {advisory.name} <span className="cell-dim">({advisory.type_index})</span>
     </>
    )}
   </h3>
   {advisory.typical_severity ? (
    <p className="field-hint">This issue class is typically {advisory.typical_severity.toLowerCase()} severity.</p>
   ) : null}
   {(advisory.description_paragraphs ?? []).map((text, i) => (
    <p className="prose" key={`d${i}`}>
     {text}
    </p>
   ))}
   {(advisory.remediation_paragraphs ?? []).length ? (
    <>
     <h3>Recommended remediation</h3>
     {(advisory.remediation_paragraphs ?? []).map((text, i) => (
      <p className="prose" key={`r${i}`}>
       {text}
      </p>
     ))}
    </>
   ) : null}
   <AdvisoryLinks label="Classifications" links={advisory.classifications} />
   <AdvisoryLinks label="References" links={advisory.references} />
  </div>
 );
}

export function AdvisoryLinks({ label, links }: { label: string; links?: AdvisoryLink[] }): JSX.Element | null {
 if (!links || links.length === 0) return null;
 return (
  <div className="stack-tight">
   <span className="eyebrow">{label}</span>
   {links.map((link) => (
    <a key={link.url} href={link.url} target="_blank" rel="noopener noreferrer" className="advisory-link">
     {link.title || link.url}
     <ExternalLink size={11} />
    </a>
   ))}
  </div>
 );
}
