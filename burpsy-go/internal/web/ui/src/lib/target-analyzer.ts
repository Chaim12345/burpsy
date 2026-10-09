import type { EngagementSeed } from "./engagement-menu";

/** GET /api/target/analyze — Burp's Target analyzer (burpsy-react-ui-dnvi). */
export interface AnalyzerURL {
  url: string;
  methods: string[];
  params: string[];
  requests: number;
  exchange_id: number;
}

export interface AnalyzerReport {
  host: string;
  path: string;
  summary: { dynamic_urls: number; static_urls: number; parameters: number; unique_parameter_names: number };
  dynamic: AnalyzerURL[];
  static: AnalyzerURL[];
  parameters: { name: string; url_count: number; urls: string[] }[];
}

/** The analyzer's query for a site-map seed: host, the branch path, and the origin when known. */
export function analyzerQuery(seed: EngagementSeed, format?: "html"): string {
  const params = new URLSearchParams({ host: seed.host });
  if (seed.path) params.set("path", seed.path);
  if (seed.port !== undefined) params.set("port", String(seed.port));
  if (seed.tls !== undefined) params.set("tls", String(seed.tls));
  if (format) params.set("format", format);
  return `/api/target/analyze?${params.toString()}`;
}
