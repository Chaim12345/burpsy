/**
 * The one severity scale (burpsy-react-ui-axm9). Burp's issue severities are a named, themeable colour
 * family; burpsy decided each finding's colour in four separate switch statements (scanner, advisories,
 * site map, dashboard), which could drift and could not be themed. This is the single answer every
 * surface reads, backed by the --severity-* tokens in styles.css (themeable through the JSON theme
 * import), so a severity looks the same wherever it is shown.
 *
 * Severity spellings arrive in three casings ("High" from findings, "HIGH" from advisories, "high"
 * from the record-issue prompt); severityKey folds them so no surface has to know which it holds.
 */
import type { Tone } from "../ui/primitives";

/** The canonical severities, most to least severe. "informational" is Burp's own word for info. */
export const SEVERITY_KEYS = ["critical", "high", "medium", "low", "informational"] as const;
export type SeverityKey = (typeof SEVERITY_KEYS)[number];

/** Fold any spelling of a severity to its canonical key, or undefined when it is not a severity. */
export function severityKey(severity: string | null | undefined): SeverityKey | undefined {
 const s = (severity ?? "").trim().toLowerCase();
 if (s === "info" || s === "information") return "informational";
 return (SEVERITY_KEYS as readonly string[]).includes(s) ? (s as SeverityKey) : undefined;
}

const TONE: Record<SeverityKey, Tone> = {
 critical: "bad",
 high: "bad",
 medium: "warn",
 low: "info",
 informational: "neutral",
};

/** The badge tone for a severity — the mapping all four surfaces used to repeat. Unknown is neutral. */
export function severityTone(severity: string | null | undefined): Tone {
 const key = severityKey(severity);
 return key ? TONE[key] : "neutral";
}

/** The themeable colour for a severity, as a CSS value: var(--severity-high) and so on. */
export function severityColor(severity: string | null | undefined): string {
 return `var(--severity-${severityKey(severity) ?? "informational"})`;
}
