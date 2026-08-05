import { PageHeader } from "../ui/layout";
import { ScopeSection } from "./settings";

/**
 * Scope sits under Target, where Burp puts it. The editor itself is shared with
 * Settings' original implementation rather than duplicated, so there is only ever
 * one place the scope rules are written from.
 */
export function ScopePage(): JSX.Element {
  return (
    <div className="page">
      <PageHeader
        title="Scope"
        description="What the proxy, scanner and crawler are allowed to touch. Changes persist immediately."
      />
      <ScopeSection />
    </div>
  );
}
