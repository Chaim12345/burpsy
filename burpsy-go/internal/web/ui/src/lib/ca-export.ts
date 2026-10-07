/**
 * CA export (burpsy-react-ui-j92x) — Burp's CA dialog's three exports: the certificate, the private
 * key, and a password-protected PKCS#12 keystore carrying both.
 *
 * POST /api/proxy/ca/export is riskDestructive, so the call goes through the confirmation gate:
 * the operator confirms in the UI, a token is minted at /api/proxy/ca/export/confirm, and that
 * token is spent on the one request. The answer is a file, not JSON, so it is read as a Blob and
 * handed straight to the browser's download — it is never decoded to text, never put in React
 * state, and never logged.
 */
import { ApiError, gatedFetch } from "./api";

export type CaExportKind = "cert" | "key" | "pkcs12";

export const CA_EXPORT_URL = "/api/proxy/ca/export";

/** The file name the server would use, for when its Content-Disposition cannot be read. */
export const CA_EXPORT_FALLBACK_NAME: Record<CaExportKind, string> = {
 cert: "burpsy-ca.crt",
 key: "burpsy-ca.key",
 pkcs12: "burpsy-ca.p12",
};

/**
 * The filename a Content-Disposition header names, or the fallback.
 *
 * Only the base name is kept: a header is server-controlled, but a download name containing a path
 * separator is never what an export means, and the browser's own sanitising differs between
 * engines.
 */
export function filenameFromDisposition(header: string | null, fallback: string): string {
 if (!header) return fallback;
 const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(header);
 let name = "";
 if (star) {
  try {
   name = decodeURIComponent((star[1] ?? "").trim());
  } catch {
   name = "";
  }
 }
 if (!name) {
  const plain = /filename\s*=\s*(?:"([^"]*)"|([^;]+))/.exec(header);
  name = (plain?.[1] ?? plain?.[2] ?? "").trim();
 }
 const base = name.split(/[/\\]/).pop() ?? "";
 return base === "" || base === "." || base === ".." ? fallback : base;
}

/** What the server refused with. The export route answers plain text, never key material. */
export function readCaExportRefusal(status: number, text: string): string {
 const trimmed = text.trim();
 if (trimmed.startsWith("{")) {
  try {
   const parsed = JSON.parse(trimmed) as { error?: unknown };
   if (typeof parsed.error === "string" && parsed.error !== "") return parsed.error;
  } catch {
   // fall through to the raw text
  }
 }
 if (trimmed !== "") return trimmed;
 return status === 503 ? "There is no signing CA to export." : `The server answered ${status}.`;
}

/** Mint, spend, and return the exported file. The password goes in the body and nowhere else. */
export async function fetchCaExport(kind: CaExportKind, password?: string): Promise<{ filename: string; blob: Blob }> {
 const body = kind === "pkcs12" ? { kind, password: password ?? "" } : { kind };
 // gatedFetch mints the gate's confirmation for this route first (the caller has already asked).
 const response = await gatedFetch(CA_EXPORT_URL, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
  cache: "no-store",
 });
 if (!response.ok) {
  // Refusals are plain text that names the problem; a 2xx body is never read as text.
  const text = await response.text();
  throw new ApiError(readCaExportRefusal(response.status, text), response.status, text);
 }
 const blob = await response.blob();
 return { filename: filenameFromDisposition(response.headers.get("content-disposition"), CA_EXPORT_FALLBACK_NAME[kind]), blob };
}
