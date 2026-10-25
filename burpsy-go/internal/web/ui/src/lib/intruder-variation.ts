/**
 * Burp's resource-pool delay variations, as the two numbers on the screen become the two the
 * server takes (burpsy-react-ui-nn0n).
 *
 * Burp's resource pool can vary the delay between requests two ways — "With random variations",
 * and an increment that lengthens every successive gap — and an attack that stays under a lockout
 * or a rate-limit window is usually an attack using one of them. burpsy's inline limits state a
 * rate rather than a delay, so the jitter is expressed as a percentage of the interval that rate
 * implies, and the increment stays in Burp's own milliseconds.
 *
 * Here rather than inline in the page for one reason: "which of these fields reaches the wire" is
 * the whole of the feature's honesty, and a rule that can be tested is a rule that cannot quietly
 * start sending a flat attack while the form says otherwise.
 */
export interface DelayVariationFields {
 delay_jitter_percent?: number;
 delay_increment_ms?: number;
}

/**
 * The wire fields for what the operator typed, or `{}` for a flat delay.
 *
 * Blank is off, and so is an explicit 0: both mean "do not vary this", and a request carrying
 * `0` for both is refused by the server as a variation with nothing to vary — a refusal the
 * operator would have earned by typing the number that means off.
 *
 * A number that is out of range is NOT dropped. The server refuses a negative increment or a
 * variation of 100% or more with a reason naming which half is impossible, and swallowing it here
 * would turn that reason into a form that quietly ran a different attack.
 */
export function delayVariationFields(jitterPercent: string, incrementMS: string): DelayVariationFields {
 const fields: DelayVariationFields = {};
 const jitter = numberOrNull(jitterPercent);
 if (jitter !== null && jitter !== 0) fields.delay_jitter_percent = jitter;
 const increment = numberOrNull(incrementMS);
 if (increment !== null && increment !== 0) fields.delay_increment_ms = increment;
 return fields;
}

/** A typed number, or null for blank and for anything that is not a finite number. */
function numberOrNull(raw: string): number | null {
 const text = raw.trim();
 if (text === "") return null;
 const value = Number(text);
 return Number.isFinite(value) ? value : null;
}
