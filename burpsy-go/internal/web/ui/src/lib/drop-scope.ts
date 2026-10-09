import type { DropScopeRule, ScopeRuleView } from "./types.policy";

/**
 * The custom drop scope's rules as the server reported them, turned back into the request shape, so
 * an add or a remove re-sends every other rule with all its arms (path, port, protocol, enabled)
 * rather than only the host the panel shows.
 */
export function dropRulesFrom(views: readonly ScopeRuleView[]): DropScopeRule[] {
 return views
  .filter((view) => view.host)
  .map((view) => {
   const rule: DropScopeRule = {
    action: view.kind === "Exclude" ? "exclude" : "include",
    pattern: view.host as string,
    enabled: view.enabled,
   };
   if (view.path) rule.path = view.path;
   if (typeof view.port === "number") rule.port = view.port;
   if (view.protocol === "http" || view.protocol === "https") rule.protocol = view.protocol;
   return rule;
  });
}

/** Whether a custom scope with these rules would be accepted: it needs an enabled include rule. */
export function dropRulesInclude(rules: readonly DropScopeRule[]): boolean {
 return rules.some((rule) => rule.action === "include" && rule.enabled !== false);
}
