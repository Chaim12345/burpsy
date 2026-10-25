import { Search, X } from "lucide-react";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { clearPendingDocPanel, pendingDocPanel, subscribeDocs } from "../lib/docs";
import { countRows, filterPanels, referencePanels } from "../lib/reference";
import { useKeymap } from "../lib/keymap";
import { PageHeader } from "../ui/layout";
import { Badge, Empty, IconButton, Input, Toolbar } from "../ui/primitives";
import { ReferencePanelView, panelAnchor } from "../ui/reference";

/**
 * Discover — Burp's DISCOVER tab, the one that used to be called Learn.
 *
 * In Burp that tab is a farm of outbound links: the Web Security Academy, the
 * manual, video tutorials, the community forum. Shipping the same shape here would
 * be worthless. burpsy has no academy to link to, PortSwigger's teaches Burp rather
 * than this tool, and a page of links is not an answer to the question an operator
 * actually arrives with, which is some version of "this scan found nothing — is
 * that the target, or is that you?".
 *
 * So this is the honest analogue: the things an operator of *this* tool otherwise
 * has to read source or docs to find. The query grammar, because the History filter
 * box is a closed typed language and nothing on screen said what it accepts. The
 * BCheck shape, because the corpus is loaded at runtime and never vendored, so
 * writing one is a real task. The hotkey sheet, because it lived only behind a
 * modal. And first on the page, deliberately, what burpsy does not do — every row
 * of that list is a way a clean result can be narrower than it looks, and honest
 * counting is this project's whole claim.
 *
 * The content is data in `lib/reference.ts` rather than markup here, so History's
 * filter-syntax modal renders the query panel from the same source instead of
 * keeping a second copy of the grammar.
 */
export function DiscoverPage(): JSX.Element {
 const [term, setTerm] = useState("");

 // A menu's "<Tool> documentation" entry (u9zz, lib/docs.ts) lands here with a panel to show:
 // the search is cleared (it could be hiding that panel), then the panel is scrolled to and
 // focused, so a keyboard or screen-reader user arrives at it rather than at the page top.
 const pendingPanel = useSyncExternalStore(subscribeDocs, pendingDocPanel, pendingDocPanel);
 useEffect(() => {
  if (!pendingPanel) return;
  setTerm("");
  const frame = requestAnimationFrame(() => {
   const target = document.getElementById(panelAnchor(pendingPanel));
   if (target) {
    target.scrollIntoView({ block: "start" });
    target.focus({ preventScroll: true });
   }
   clearPendingDocPanel();
  });
  return () => cancelAnimationFrame(frame);
 }, [pendingPanel]);

 // Subscribed, so a rebind in Settings shows here too. Discover exists to tell the operator
 // what the keys are; printing the shipped defaults after they changed one would make it the
 // least trustworthy page in the console.
 const keymap = useKeymap();
 const all = useMemo(() => referencePanels(keymap), [keymap]);
 const panels = useMemo(() => filterPanels(all, term), [all, term]);
 const total = useMemo(() => countRows(all), [all]);
 const shown = countRows(panels);

 return (
  <div className="page">
   <PageHeader
    title="Discover"
    description="An in-app reference for operating burpsy: the filter grammar, the BCheck shape, the hotkeys, and the gaps that change how a result should be read."
   />

   <Toolbar>
    <div className="search-field">
     <Search size={15} />
     <Input
      aria-label="Search the reference"
      title="Search the reference"
      value={term}
      onChange={(event) => setTerm(event.target.value)}
      placeholder="collaborator, insertion point, append-only…"
     />
     {term ? (
      <IconButton label="Clear search" size="small" onClick={() => setTerm("")}>
       <X size={13} />
      </IconButton>
     ) : null}
    </div>
    <Badge tone={term ? "info" : "neutral"}>{term ? `${shown} of ${total} entries` : `${total} entries`}</Badge>
   </Toolbar>

   {panels.length ? (
    <>
     {/* A contents row rather than a sidebar: nine sections is enough to need one and
              not enough to earn a column of the viewport, which on a console this dense is
              the more expensive of the two. It follows the filter, so it never offers a
              destination the search has just removed. */}
     <nav className="reference-jump" aria-label="Reference sections">
      {panels.map((panel) => (
       <button
        key={panel.id}
        type="button"
        className="reference-jump-link"
        onClick={() => document.getElementById(panelAnchor(panel.id))?.scrollIntoView({ block: "start", behavior: "smooth" })}
       >
        {panel.title}
       </button>
      ))}
     </nav>
     {panels.map((panel) => (
      <ReferencePanelView key={panel.id} panel={panel} />
     ))}
    </>
   ) : (
    /* The only empty state this page can reach, and it is a search miss rather than
           an absence of data — so it names what is searched instead of inviting a retry
           of the same word. */
    <Empty
     title={`Nothing in the reference matches “${term}”`}
     detail="A search matches an entry's term, its explanation and its caveat, plus each section's title and code samples. Try collaborator, insertion point, append-only, or mod."
    />
   )}
  </div>
 );
}
