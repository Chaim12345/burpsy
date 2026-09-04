import type { ReferencePanel } from "../lib/reference";
import { SectionHeading } from "./layout";
import { Kbd } from "./primitives";

/** The DOM id a panel renders under, so the contents row can scroll to it. */
export function panelAnchor(id: string): string {
  return `reference-${id}`;
}

/**
 * One reference panel: heading, any monospace blocks, then the term/meaning rows.
 *
 * Lives in `ui/` rather than inside the Discover page because two surfaces render
 * it — Discover renders every panel, and History's filter-syntax modal renders the
 * query panel alone. Before this existed the modal carried its own copy of the
 * grammar, which is how a filter box ends up documented with fields the parser no
 * longer has.
 *
 * A `<dl>` rather than a table: these are term/definition pairs with nothing to
 * sort and no column that means the same thing across two panels, both of which a
 * table would imply.
 */
export function ReferencePanelView({
  panel,
  /** The modal caller supplies its own dialog title, so it turns this off. */
  showHeading = true,
}: {
  panel: ReferencePanel;
  showHeading?: boolean;
}): JSX.Element {
  return (
    <section className="reference-panel" id={panelAnchor(panel.id)}>
      {showHeading ? <SectionHeading title={panel.title} detail={panel.summary} /> : null}

      {(panel.blocks ?? []).map((block) => (
        <div className="reference-block" key={block.label}>
          <div className="reference-block-label">{block.label}</div>
          <pre>{block.body}</pre>
        </div>
      ))}

      <dl className="reference-rows">
        {panel.rows.map((row) => (
          <div key={row.term}>
            <dt>
              {row.keys ? (
                <span className="reference-keys">
                  {row.keys.map((key, index) => (
                    <span key={key}>
                      {index > 0 ? "+" : null}
                      <Kbd>{key}</Kbd>
                    </span>
                  ))}
                </span>
              ) : (
                row.term
              )}
            </dt>
            <dd>
              {row.detail}
              {row.note ? <small className="reference-note">{row.note}</small> : null}
            </dd>
          </div>
        ))}
      </dl>

      {/* Named so a reader can check the page against the tree rather than trusting it. */}
      <p className="reference-source">{panel.source}</p>
    </section>
  );
}
