import { emptyIntruderConfig, type GrepMatchMode, type IntruderConfig } from "./store";
import { ATTACK_MODES, PAYLOAD_RULES } from "./types.tools";

/**
 * Burp's "Save attack config" / "Load attack config", as a file this browser writes and reads.
 *
 * Burp keeps an attack configuration in the project file; burpsy has no project file, so the
 * carrier is a JSON document the operator downloads and picks back up. That is only honest if the
 * document holds EVERY field the Intruder page holds — a loader that silently drops the payload
 * processing rules would hand back an attack that looks like the saved one and sends different
 * requests. So the format is the whole `IntruderConfig`, and the reader refuses a document it
 * cannot restore in full, naming the field, rather than filling the gap with a default.
 *
 * The field table below is typed `Record<keyof IntruderConfig, Check>`: adding a field to
 * IntruderConfig without adding a check here is a type error, not a silently unsaved field.
 */

export const ATTACK_CONFIG_FORMAT = "burpsy-intruder-attack";
export const ATTACK_CONFIG_VERSION = 1;

/** What a save writes and a load expects. */
export interface AttackConfigFile {
  format: string;
  version: number;
  config: IntruderConfig;
}

/** A field check: null when the value is restorable, otherwise the reason it is not. */
type Check = (value: unknown) => string | null;

/** Burp's auto-pause condition: pause when an expression APPEARS, or when it stops appearing. */
export const AUTO_PAUSE_MODES = ["appears", "missing"] as const;

const ATTACK_MODE_VALUES = ATTACK_MODES.map((mode) => mode.value) as string[];
const PAYLOAD_RULE_VALUES = PAYLOAD_RULES.map((rule) => rule.value) as string[];
const PAYLOAD_TYPE_VALUES = [
  "list",
  "numbers",
  "file",
  "brute_force",
  "dates",
  "custom_iterator",
  "null",
] as string[];
const GREP_MATCH_MODES: GrepMatchMode[] = ["simple", "regex"];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const str: Check = (value) => (typeof value === "string" ? null : `expected a string, found ${typeName(value)}`);
const bool: Check = (value) => (typeof value === "boolean" ? null : `expected true or false, found ${typeName(value)}`);
/** Finite numbers only: NaN and Infinity survive neither JSON nor the run request. */
const num: Check = (value) =>
  typeof value === "number" && Number.isFinite(value) ? null : `expected a number, found ${typeName(value)}`;
const int: Check = (value) =>
  typeof value === "number" && Number.isInteger(value) ? null : `expected a whole number, found ${typeName(value)}`;

function typeName(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  if (typeof value === "string") return `the string ${JSON.stringify(value)}`;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === undefined) return "nothing";
  return "an object";
}

function oneOf(allowed: string[]): Check {
  return (value) => {
    if (typeof value !== "string") return `expected one of ${allowed.join(", ")}, found ${typeName(value)}`;
    return allowed.includes(value) ? null : `${JSON.stringify(value)} is not one of ${allowed.join(", ")}`;
  };
}

function arrayOf(item: Check): Check {
  return (value) => {
    if (!Array.isArray(value)) return `expected an array, found ${typeName(value)}`;
    for (let i = 0; i < value.length; i++) {
      const reason = item(value[i]);
      if (reason) return `[${i}] ${reason}`;
    }
    return null;
  };
}

/** An object with exactly these keys — an extra key means the writer knew something this reader does not. */
function shape(fields: Record<string, Check>): Check {
  const expected = Object.keys(fields);
  return (value) => {
    if (!isPlainObject(value)) return `expected an object, found ${typeName(value)}`;
    for (const key of Object.keys(value)) {
      if (!expected.includes(key)) return `has an unknown key ${JSON.stringify(key)}`;
    }
    for (const key of expected) {
      if (!(key in value)) return `is missing ${JSON.stringify(key)}`;
      const reason = fields[key]!(value[key]);
      if (reason) return `.${key} ${reason}`;
    }
    return null;
  };
}

/**
 * One check per IntruderConfig field. The `Record<keyof IntruderConfig, …>` annotation is the
 * guard that matters: a new attack-configuration field that nobody adds here fails `tsc`, so the
 * file format cannot fall behind the page without the build saying so.
 */
const CHECKS: Record<keyof IntruderConfig, Check> = {
  msgId: str,
  target: str,
  label: str,
  mode: oneOf(ATTACK_MODE_VALUES),
  allPoints: bool,
  points: arrayOf(
    shape({ index: int, kind: str, label: str, offset: int, len: int, current: str }),
  ),
  selected: arrayOf(int),
  payloadTexts: arrayOf(str),
  payloadTypes: arrayOf(oneOf(PAYLOAD_TYPE_VALUES)),
  payloadNumbers: arrayOf(shape({ from: str, to: str, step: str })),
  payloadFiles: arrayOf(str),
  payloadBrute: arrayOf(shape({ charset: str, min_len: str, max_len: str })),
  payloadDates: arrayOf(shape({ from: str, to: str, step: str, format: str })),
  payloadCustom: arrayOf(shape({ positions: str, separator: str })),
  payloadNulls: arrayOf(str),
  rules: arrayOf(
    shape({
      rule: oneOf(PAYLOAD_RULE_VALUES),
      text: str,
      pattern: str,
      replace: str,
      all: bool,
      layer: str,
      algorithm: str,
      form: str,
    }),
  ),
  grepMatch: str,
  grepMatchMode: oneOf(GREP_MATCH_MODES),
  grepExtract: str,
  poolName: str,
  maxRequests: num,
  maxInFlight: num,
  rps: str,
  // Fields the page grew after this format was first written. They are here because the guard
  // above made adding them compulsory rather than optional: a saved attack that silently dropped
  // its manual markers or its rate variation would reload as a DIFFERENT attack that looks like
  // the saved one — the precise failure this file exists to prevent.
  manualSpans: arrayOf(shape({ start: int, end: int, text: str })),
  grepMatchList: arrayOf(str),
  grepMatchCaseSensitive: bool,
  grepMatchExcludeHeaders: bool,
  // The resource pool's delay variation (burpsy-react-ui-nn0n). Held as text by the page, so saved
  // as text: "" is "not set", which is not the same attack as an explicit 0.
  delayJitterPct: str,
  delayIncrementMS: str,
  retries: str,
  retryDelayMS: str,
  baseline: bool,
  // Burp's Set Connection header and Store full payloads (fmxv). Booleans, like baseline: an
  // attack either sends Connection: close on every request or it does not, and there is no
  // third state a saved configuration could be in.
  setConnectionClose: bool,
  storePayloads: bool,
  // Burp's per-request response timeout (mmca). Text, like retries: "" is "the standing read
  // timeout", which is not the same attack as any number.
  responseTimeoutMS: str,
  // Burp's auto-pause (2cvk). The block is saved whole, enabled flag first, because a saved
  // configuration that dropped it would resume as a different attack that looks like the saved
  // one — the exact failure this file exists to prevent, and the one fmxv's settings had.
  autoPauseEnabled: bool,
  autoPauseMode: oneOf([...AUTO_PAUSE_MODES]),
  autoPauseExpressions: arrayOf(str),
  autoPauseSimple: bool,
  autoPauseCaseSensitive: bool,
};

/** The fields a saved attack configuration carries, in the order the store declares them. */
export const ATTACK_CONFIG_FIELDS = Object.keys(emptyIntruderConfig()) as (keyof IntruderConfig)[];

/** The whole configuration as a document, pretty-printed because an operator reads and diffs these. */
export function serializeAttackConfig(config: IntruderConfig): string {
  const ordered: Record<string, unknown> = {};
  // Written in the store's declaration order rather than whatever order the live object acquired,
  // so two saves of the same attack are byte-identical and `diff` says what actually changed.
  for (const key of ATTACK_CONFIG_FIELDS) ordered[key] = config[key];
  const file: Record<string, unknown> = {
    format: ATTACK_CONFIG_FORMAT,
    version: ATTACK_CONFIG_VERSION,
    config: ordered,
  };
  return `${JSON.stringify(file, null, 2)}\n`;
}

export type AttackConfigParse =
  | { ok: true; config: IntruderConfig }
  | { ok: false; reason: string };

/**
 * Read a saved attack configuration, or refuse it saying which field stopped the load.
 *
 * Refusal is the whole point. A loader that skipped an unreadable field would leave the page
 * holding a mixture of the file and whatever was there before, which is an attack configuration
 * nobody wrote — and the operator would find out by reading a report produced by requests they did
 * not intend. Unknown keys are refused for the same reason in the other direction: a file written
 * by a newer burpsy carries settings this one would drop on the floor.
 */
export function parseAttackConfig(text: string): AttackConfigParse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { ok: false, reason: `This is not JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (!isPlainObject(parsed)) {
    return { ok: false, reason: `A saved attack configuration is a JSON object; this file holds ${typeName(parsed)}.` };
  }
  if (parsed.format !== ATTACK_CONFIG_FORMAT) {
    return {
      ok: false,
      reason: `"format" is ${typeName(parsed.format)}, not ${JSON.stringify(ATTACK_CONFIG_FORMAT)} — this is not a burpsy Intruder attack configuration.`,
    };
  }
  if (parsed.version !== ATTACK_CONFIG_VERSION) {
    return {
      ok: false,
      reason: `"version" is ${typeName(parsed.version)}; this burpsy reads version ${ATTACK_CONFIG_VERSION} only.`,
    };
  }
  const raw = parsed.config;
  if (!isPlainObject(raw)) {
    return { ok: false, reason: `"config" is ${typeName(raw)}, not an object.` };
  }
  for (const key of Object.keys(raw)) {
    if (!(ATTACK_CONFIG_FIELDS as string[]).includes(key)) {
      return {
        ok: false,
        reason: `"config" carries ${JSON.stringify(key)}, which this burpsy does not know how to restore. Refusing rather than dropping it.`,
      };
    }
  }
  for (const key of ATTACK_CONFIG_FIELDS) {
    if (!(key in raw)) {
      return { ok: false, reason: `"config.${key}" is missing, so this attack cannot be restored in full.` };
    }
    const reason = CHECKS[key](raw[key]);
    if (reason) return { ok: false, reason: `"config.${key}" ${reason}.` };
  }
  const config = {} as Record<string, unknown>;
  for (const key of ATTACK_CONFIG_FIELDS) config[key] = raw[key];
  return { ok: true, config: config as unknown as IntruderConfig };
}

/** A filename that sorts by save time and says what it is. */
export function attackConfigFilename(now: Date = new Date()): string {
  const stamp = now.toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  return `burpsy-attack-${stamp}.json`;
}
