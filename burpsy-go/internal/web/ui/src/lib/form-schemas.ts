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

const portSchema = wholeNumber("Enter a port between 1 and 65535").pipe(z.number().int().min(1, "Enter a port between 1 and 65535").max(65535, "Enter a port between 1 and 65535"));

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
  dir: z.string().trim().transform((dir) => (dir === "" ? undefined : dir)),
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
