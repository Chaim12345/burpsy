import { esc } from "./common";

type SyntaxKind = "http" | "auto";

function span(cls: string, value: string): string {
  return `<span class="${cls}">${esc(value)}</span>`;
}

function highlightJsonValue(value: unknown, depth = 0): string {
  const indent = "  ".repeat(depth);
  const childIndent = "  ".repeat(depth + 1);
  if (value === null) return span("syn-null", "null");
  if (typeof value === "string") return span("syn-string", JSON.stringify(value));
  if (typeof value === "number") return span("syn-number", String(value));
  if (typeof value === "boolean") return span("syn-boolean", String(value));
  if (Array.isArray(value)) {
    if (!value.length) return span("syn-punc", "[]");
    return `${span("syn-punc", "[")}\n${value
      .map((item) => `${childIndent}${highlightJsonValue(item, depth + 1)}`)
      .join(`${span("syn-punc", ",")}\n`)}\n${indent}${span("syn-punc", "]")}`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (!entries.length) return span("syn-punc", "{}");
    return `${span("syn-punc", "{")}\n${entries
      .map(
        ([key, item]) =>
          `${childIndent}${span("syn-key", JSON.stringify(key))}${span("syn-punc", ":")} ${highlightJsonValue(item, depth + 1)}`,
      )
      .join(`${span("syn-punc", ",")}\n`)}\n${indent}${span("syn-punc", "}")}`;
  }
  return esc(String(value));
}

function highlightJson(raw: string): string | null {
  try {
    return highlightJsonValue(JSON.parse(raw));
  } catch {
    return null;
  }
}

function highlightMarkup(raw: string): string {
  let out = "";
  let cursor = 0;
  const token = /<!--[^]*?-->|<\/?[A-Za-z][^>]*>|&(?:#\d+|#x[\da-f]+|[A-Za-z]+);/gi;
  for (const match of raw.matchAll(token)) {
    const index = match.index ?? 0;
    out += esc(raw.slice(cursor, index));
    const value = match[0];
    if (value.startsWith("<!--")) {
      out += span("syn-comment", value);
    } else if (value.startsWith("&")) {
      out += span("syn-entity", value);
    } else {
      const tag = /^(<\/?)([\w:-]+)([^>]*)(>)$/.exec(value);
      if (!tag) out += esc(value);
      else {
        const opening = tag[1]!;
        const name = tag[2]!;
        const rawAttrs = tag[3]!;
        const closing = tag[4]!;
        let attrs = "";
        let attrCursor = 0;
        const attrToken = /([\w:-]+)(\s*=\s*)("[^"]*"|'[^']*')/g;
        for (const attr of rawAttrs.matchAll(attrToken)) {
          const attrIndex = attr.index ?? 0;
          attrs += esc(rawAttrs.slice(attrCursor, attrIndex));
          attrs += `${span("syn-attr", attr[1]!)}${esc(attr[2]!)}${span("syn-string", attr[3]!)}`;
          attrCursor = attrIndex + attr[0].length;
        }
        attrs += esc(rawAttrs.slice(attrCursor));
        out += `${span("syn-punc", opening)}${span("syn-tag", name)}${attrs}${span("syn-punc", closing)}`;
      }
    }
    cursor = index + value.length;
  }
  return out + esc(raw.slice(cursor));
}

function highlightForm(raw: string): string {
  return raw
    .split("&")
    .map((part) => {
      const at = part.indexOf("=");
      if (at < 0) return span("syn-key", part);
      return `${span("syn-key", part.slice(0, at))}${span("syn-punc", "=")}${span("syn-string", part.slice(at + 1))}`;
    })
    .join(span("syn-punc", "&"));
}

function highlightBody(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  const json = (trimmed.startsWith("{") || trimmed.startsWith("[")) && highlightJson(trimmed);
  if (json) return json;
  if (trimmed.startsWith("<")) return highlightMarkup(raw);
  if (/^[^\s=&]+=[^\n]*(?:&[^\s=&]+=[^\n]*)+$/.test(trimmed)) return highlightForm(trimmed);
  return esc(raw);
}

function highlightStartLine(line: string): string {
  const response = /^(HTTP\/\S+)\s+(\d{3})(?:\s+(.*))?$/.exec(line);
  if (response) {
    return `${span("syn-protocol", response[1]!)} ${span("syn-status", response[2]!)}${response[3] ? ` ${span("syn-reason", response[3])}` : ""}`;
  }
  const request = /^(\S+)\s+(\S+)\s+(HTTP\/\S+)$/.exec(line);
  if (request) {
    return `${span("syn-method", request[1]!)} ${span("syn-target", request[2]!)} ${span("syn-protocol", request[3]!)}`;
  }
  return esc(line);
}

export function highlightHttp(raw: string): string {
  const normalized = raw.replace(/\r\n/g, "\n");
  const split = normalized.indexOf("\n\n");
  const head = split >= 0 ? normalized.slice(0, split) : normalized;
  const body = split >= 0 ? normalized.slice(split + 2) : "";
  const lines = head.split("\n");
  const highlighted = lines.map((line, index) => {
    if (index === 0) return highlightStartLine(line);
    const at = line.indexOf(":");
    if (at < 1) return esc(line);
    return `${span("syn-header", line.slice(0, at))}${span("syn-punc", ":")} ${span("syn-header-value", line.slice(at + 1).trimStart())}`;
  });
  return highlighted.join("\n") + (split >= 0 ? `\n\n${highlightBody(body)}` : "");
}

export function highlightAuto(raw: string): string {
  const trimmed = raw.trim();
  if (/^(?:[A-Z]+\s+\S+\s+HTTP\/|HTTP\/\S+\s+\d{3})/.test(trimmed)) return highlightHttp(raw);
  const json = highlightJson(trimmed);
  if (json) return json;
  if (trimmed.startsWith("<")) return highlightMarkup(raw);
  return esc(raw);
}

export function renderSyntax(element: HTMLElement, raw: string, kind: SyntaxKind = "auto"): void {
  element.classList.add("syntax-view");
  element.innerHTML = kind === "http" ? highlightHttp(raw) : highlightAuto(raw);
}

export function refreshSyntaxEditor(textarea: HTMLTextAreaElement, kind: SyntaxKind = "http"): void {
  const wrapper = textarea.closest<HTMLElement>(".syntax-editor");
  const layer = wrapper?.querySelector<HTMLElement>("pre");
  if (!layer) return;
  layer.innerHTML = kind === "http" ? highlightHttp(textarea.value) : highlightAuto(textarea.value);
  layer.scrollTop = textarea.scrollTop;
  layer.scrollLeft = textarea.scrollLeft;
}

export function wireSyntaxEditor(textarea: HTMLTextAreaElement, kind: SyntaxKind = "http"): void {
  if (textarea.closest(".syntax-editor")) {
    refreshSyntaxEditor(textarea, kind);
    return;
  }
  const parent = textarea.parentElement;
  if (!parent) return;
  const wrapper = document.createElement("div");
  wrapper.className = "syntax-editor";
  const layer = document.createElement("pre");
  layer.className = "syntax-view";
  layer.setAttribute("aria-hidden", "true");
  parent.insertBefore(wrapper, textarea);
  wrapper.append(layer, textarea);
  const refresh = () => refreshSyntaxEditor(textarea, kind);
  textarea.addEventListener("input", refresh);
  textarea.addEventListener("scroll", refresh);
  refresh();
}
