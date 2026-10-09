/**
 * What a scope actually authorises (burpsy-react-ui-us6r.1).
 *
 * The badge used to read `allow_all` alone, so an emptied scope — no include rules — showed
 * "restricted" in the good tone while core/scope.go's Contains let every host through ("With no
 * include rules, everything not excluded is in scope"). Every badge and status line reads this one
 * answer instead.
 */
export interface ScopeLike {
 allow_all?: boolean;
 rules?: readonly { include?: boolean; kind?: string; enabled?: boolean }[];
}

function isInclude(rule: { include?: boolean; kind?: string }): boolean {
 if (typeof rule.include === "boolean") return rule.include;
 return (rule.kind ?? "").toLowerCase() === "include";
}

/** True when every host that no exclude rule names is in scope. */
export function scopeAllowsEverything(scope: ScopeLike | undefined | null): boolean {
 if (!scope) return false;
 if (scope.allow_all) return true;
 // A disabled rule "takes no part in any scope decision" (types.policy.ts), so it restricts nothing.
 return !(scope.rules ?? []).some((rule) => rule.enabled !== false && isInclude(rule));
}

/** The badge's words and tone. */
export function scopeBadge(scope: ScopeLike): { label: string; tone: "warn" | "good" } {
 if (!scopeAllowsEverything(scope)) return { label: "restricted", tone: "good" };
 const excludes = (scope.rules ?? []).filter((rule) => rule.enabled !== false && !isInclude(rule)).length;
 return { label: excludes ? "everything not excluded is in scope" : "everything in scope", tone: "warn" };
}
