/**
 * Zod schemas for the Settings forms (burpsy-react-ui-vlrh). Form fields hold text; the schema is
 * the one place that turns it into the numbers the API takes and says why it cannot, so no form
 * hand-rolls Number()/parseInt() and an error message is written once.
 *
 * Used through react-hook-form's zodResolver (lib/use-zod-form.ts).
 */
import { z } from "zod";

/** Text that is a whole number — "42", " -1 " — and nothing else: not "", "4.5", "1e3" or "0x10". */
export function wholeNumber(message: string) {
 return z
  .string()
  .trim()
  .regex(/^-?\d+$/, message)
  .transform(Number);
}

const portSchema = wholeNumber("Enter a port between 1 and 65535").pipe(
 z.number().int().min(1, "Enter a port between 1 and 65535").max(65535, "Enter a port between 1 and 65535"),
);

/** Protocol negotiation probe: a host, a port, and whether to use TLS. */
export const probeSchema = z.object({
 host: z.string().trim().min(1, "Enter a host"),
 port: portSchema,
 tls: z.boolean(),
});
export type ProbeForm = z.input<typeof probeSchema>;

/** Optional retention: blank or 0 leave the server default (0 never meant "keep none"); -1 never prunes. */
const retentionOrDefault = z
 .string()
 .trim()
 .transform((text, ctx) => {
  if (text === "") return undefined;
  if (!/^-?\d+$/.test(text)) {
   ctx.addIssue({ code: "custom", message: "Keep must be a whole number (-1 never prunes)" });
   return z.NEVER;
  }
  const count = Number(text);
  if (count < -1) {
   ctx.addIssue({ code: "custom", message: "Keep must be -1 (never prune) or more" });
   return z.NEVER;
  }
  return count === 0 ? undefined : count;
 });

/** "Back up now": directory and retention both optional. */
export const backupNowSchema = z.object({
 dir: z
  .string()
  .trim()
  .transform((dir) => (dir === "" ? undefined : dir)),
 retention: retentionOrDefault,
});
export type BackupNowForm = z.input<typeof backupNowSchema>;

/** The automatic backup setting. Retention is saved as 0 when blank or 0, which the server reads as its default. */
export const autoBackupSchema = z
 .object({
  interval: wholeNumber("The backup interval must be a whole number of minutes (0 turns it off).").pipe(
   z.number().min(0, "The backup interval must be a whole number of minutes (0 turns it off)."),
  ),
  dir: z.string().trim(),
  retention: retentionOrDefault,
 })
 .transform(({ interval, dir, retention }) => ({ interval_minutes: interval, dir, retention: retention ?? 0 }));
export type AutoBackupForm = z.input<typeof autoBackupSchema>;

/** A resource pool (Settings > Resource pools). Mirrors the server's own refusals, so a bad pool is never sent. */
export const poolSchema = z
 .object({
  name: z.string().trim().min(1, "Enter a pool name"),
  maxConcurrent: wholeNumber("Max concurrent requests must be a whole number").pipe(
   z.number().min(1, "Max concurrent requests must be at least 1"),
  ),
  delay: wholeNumber("The delay must be a whole number of milliseconds").pipe(z.number().min(0, "The delay cannot be negative")),
  throttle: z.boolean(),
  // Only read while throttling is on, so a stale value in a hidden field never blocks a save.
  increment: z.string().trim(),
 })
 .transform((value, ctx) => {
  let increment_ms = 0;
  if (value.throttle) {
   if (!/^\d+$/.test(value.increment) || Number(value.increment) < 1) {
    ctx.addIssue({ code: "custom", path: ["increment"], message: "The throttle increment must be a whole number above 0" });
    return z.NEVER;
   }
   increment_ms = Number(value.increment);
   if (value.delay <= 0) {
    ctx.addIssue({ code: "custom", path: ["delay"], message: "Automatic throttling needs a delay above 0" });
    return z.NEVER;
   }
  }
  return {
   name: value.name,
   max_concurrent: value.maxConcurrent,
   delay_ms: value.delay,
   throttle: value.throttle ? { increment_ms } : null,
  };
 });
export type PoolForm = z.input<typeof poolSchema>;

/** A schedule's repeat interval, typed in hours (fractions allowed), saved as whole seconds. */
export const intervalHoursSchema = z
 .string()
 .trim()
 .regex(/^\d+(\.\d+)?$/, "Enter the interval in hours, e.g. 24 or 0.5")
 .transform(Number)
 .pipe(z.number().min(1 / 60, "The interval must be at least 1 minute"))
 .transform((hours) => Math.max(1, Math.round(hours * 3600)));
