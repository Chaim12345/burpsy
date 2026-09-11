import { useState, type ChangeEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, Empty, Input, Button, Badge, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";
import { api, downloadText } from "../lib/api";

// Burp's Engagement tools over the site map (burpsy-react-ui-1s07): Find comments, Find
// scripts and Find references. One view, three searches — server-side over the stored
// responses, because the bodies live in the store and pulling every response to the browser
// to regex it there would trade one request for N.

export interface EngagementRow {
 exchange_id: number;
 host: string;
 port: number;
 tls: boolean;
 path: string;
 snippet: string;
}

export interface EngagementResult {
 kind: string;
 matches: number;
 truncated: boolean;
 rows: EngagementRow[];
}

const KINDS = [
 { id: "comments", label: "Find comments" },
 { id: "scripts", label: "Find scripts" },
 { id: "references", label: "Find references to…" },
] as const;

type KindId = (typeof KINDS)[number]["id"];

export function EngagementView() {
 const [kind, setKind] = useState<KindId>("comments");
 const [term, setTerm] = useState("");
 const [submitted, setSubmitted] = useState<{ kind: KindId; q: string }>({ kind: "comments", q: "" });

 const search = useQuery({
  queryKey: ["engagement", submitted.kind, submitted.q],
  queryFn: () => {
   const params = new URLSearchParams();
   if (submitted.q.trim()) params.set("q", submitted.q.trim());
   params.set("limit", "200");
   const qs = params.toString();
   return api<EngagementResult>(`/api/engagement/${submitted.kind}${qs ? `?${qs}` : ""}`);
  },
  enabled: true,
 });

 const run = (k: KindId) => {
  setKind(k);
  setSubmitted({ kind: k, q: term });
 };

 const rows = search.data?.rows ?? [];
 const exportCsv = () => {
  const header = "Exchange,Host,Port,TLS,Path,Match";
  const body = rows
   .map((r) =>
    [r.exchange_id, r.host, r.port, r.tls ? "yes" : "no", r.path, r.snippet]
     .map((cell) => {
      const s = String(cell);
      return /["\n,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
     })
     .join(","),
   )
   .join("\n");
  downloadText(`engagement-${submitted.kind}.csv`, [header, body].filter((l) => l !== undefined).join("\n"));
 };

 return (
  <div className="pane">
   <Toolbar className="pane-toolbar">
    <div role="group" aria-label="Engagement search kind" className="chip-row">
     {KINDS.map((k) => (
      <Button
       key={k.id}
       variant={kind === k.id ? "outline" : "quiet"}
       size="small"
       aria-pressed={kind === k.id}
       onClick={() => run(k.id)}
      >
       {k.label}
      </Button>
     ))}
    </div>
    <Input
     aria-label="Engagement search target URL"
     title="For Find references: the URL to look for in href/src/action attributes. Ignored by the other two searches."
     value={term}
     onChange={(event: ChangeEvent<HTMLInputElement>) => setTerm(event.target.value)}
     placeholder={kind === "references" ? "URL to find references to…" : "not used by this search"}
     style={{ maxWidth: "var(--w-md)" }}
     disabled={kind !== "references"}
    />
    <Button variant="outline" size="small" onClick={() => setSubmitted({ kind, q: term })}>
     Search
    </Button>
    {search.data ? (
     <>
      <Badge>
       {search.data.matches.toLocaleString()} match{search.data.matches === 1 ? "" : "es"}
      </Badge>
      {search.data.truncated ? <Badge tone="warn">showing first {rows.length}</Badge> : null}
      {rows.length > 0 ? (
       <Button variant="outline" size="small" onClick={exportCsv}>
        Export CSV
       </Button>
      ) : null}
     </>
    ) : null}
   </Toolbar>
   {search.isFetching ? (
    <Empty title="Searching…" detail="Reading the responses the site map holds." />
   ) : search.isError ? (
    <Empty
     title="The search failed"
     detail={search.error instanceof Error ? search.error.message : "The store could not be read."}
    />
   ) : rows.length === 0 ? (
    <Empty
     title="No matches in the captured responses"
     detail="The site map searches what has been captured — run traffic through the proxy or a crawl first."
    />
   ) : (
    <Card className="pane-fill">
     <SimpleTable headers={["Exchange", "Host", "Path", "Match"]}>
      {rows.map((row) => (
       <tr key={`${row.exchange_id}-${row.snippet.slice(0, 40)}`}>
        <td>
         <span className="cell-num">#{row.exchange_id}</span>
        </td>
        <td>
         {row.host}
         {row.port !== 80 && row.port !== 443 ? `:${row.port}` : ""}
        </td>
        <td className="cell-dim">{row.path}</td>
        <td>
         <code style={{ fontSize: "0.85em" }}>{row.snippet}</code>
        </td>
       </tr>
      ))}
     </SimpleTable>
    </Card>
   )}
  </div>
 );
}
