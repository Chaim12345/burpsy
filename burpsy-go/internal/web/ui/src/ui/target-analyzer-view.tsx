import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { api } from "../lib/api";
import type { EngagementSeed } from "../lib/engagement-menu";
import { analyzerQuery, type AnalyzerReport, type AnalyzerURL } from "../lib/target-analyzer";
import { LoadingPanel, SectionHeading } from "./layout";
import { Badge, Button, Card, Empty, ErrorNotice } from "./primitives";
import { SimpleTable } from "./table";

type Tab = "summary" | "dynamic" | "static" | "parameters";

/**
 * Burp's Target analyzer (burpsy-react-ui-dnvi): Summary, Dynamic URLs, Static URLs and Parameters
 * for a host or branch, over what the site map already holds. "Save report" downloads the HTML report.
 */
export function TargetAnalyzerView({ seed }: { seed: EngagementSeed | undefined }): JSX.Element {
 const [tab, setTab] = useState<Tab>("summary");
 const [selectedParam, setSelectedParam] = useState<string | null>(null);
 const { data, error, isLoading, refetch } = useQuery({
  queryKey: ["target-analyzer", seed?.host, seed?.path, seed?.port, seed?.tls],
  queryFn: ({ signal }) => api<AnalyzerReport>(analyzerQuery(seed as EngagementSeed), { signal }),
  enabled: seed !== undefined,
 });
 if (!seed) {
  return (
   <Card>
    <Empty
     title="Nothing analysed yet"
     detail="Right-click a host or branch in the site map and choose Engagement tools › Target analyzer."
    />
   </Card>
  );
 }
 const urlRows = (rows: AnalyzerURL[], withParams: boolean) => (
  <SimpleTable headers={withParams ? ["URL", "Methods", "Parameters", "Requests"] : ["URL", "Methods", "Requests"]}>
   {rows.map((row) => (
    <tr key={row.url}>
     <td>
      <code>{row.url}</code>
     </td>
     <td>{row.methods.join(", ")}</td>
     {withParams ? <td>{row.params.join(", ")}</td> : null}
     <td>{row.requests}</td>
    </tr>
   ))}
  </SimpleTable>
 );
 const tabs: [Tab, string][] = [
  ["summary", "Summary"],
  ["dynamic", `Dynamic URLs (${data?.summary.dynamic_urls ?? 0})`],
  ["static", `Static URLs (${data?.summary.static_urls ?? 0})`],
  ["parameters", `Parameters (${data?.summary.unique_parameter_names ?? 0})`],
 ];
 const param = data?.parameters.find((p) => p.name === selectedParam);
 return (
  <Card>
   <SectionHeading
    title={`Target analyzer: ${seed.host}${seed.path}`}
    detail="Counts over the content already captured for this host or branch. A URL is dynamic when a captured request to it carried a query or form parameter, and static otherwise — its response may still be generated."
    actions={
     <Button variant="outline" size="small" onClick={() => window.open(analyzerQuery(seed, "html"), "_blank")}>
      <Download size={13} />
      Save report
     </Button>
    }
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {isLoading ? <LoadingPanel label="Analysing the captured content" /> : null}
   {data ? (
    <>
     <div role="tablist" aria-label="Target analyzer" className="toolbar">
      {tabs.map(([id, label]) => (
       <Button
        key={id}
        role="tab"
        aria-selected={tab === id}
        variant={tab === id ? "outline" : "quiet"}
        size="small"
        onClick={() => setTab(id)}
       >
        {label}
       </Button>
      ))}
     </div>
     {tab === "summary" ? (
      <SimpleTable headers={["Measure", "Count"]}>
       <tr>
        <td>Dynamic URLs</td>
        <td>{data.summary.dynamic_urls}</td>
       </tr>
       <tr>
        <td>Static URLs</td>
        <td>{data.summary.static_urls}</td>
       </tr>
       <tr>
        <td>Parameters</td>
        <td>{data.summary.parameters}</td>
       </tr>
       <tr>
        <td>Unique parameter names</td>
        <td>{data.summary.unique_parameter_names}</td>
       </tr>
      </SimpleTable>
     ) : null}
     {tab === "dynamic" ? (
      data.dynamic.length ? (
       urlRows(data.dynamic, true)
      ) : (
       <Empty title="No dynamic URLs" detail="No captured request here carried a parameter." />
      )
     ) : null}
     {tab === "static" ? (
      data.static.length ? (
       urlRows(data.static, false)
      ) : (
       <Empty title="No static URLs" detail="Every captured URL here took parameters." />
      )
     ) : null}
     {tab === "parameters" ? (
      data.parameters.length ? (
       <>
        <SimpleTable headers={["Parameter", "URLs"]}>
         {data.parameters.map((p) => (
          <tr key={p.name} aria-selected={p.name === selectedParam} onClick={() => setSelectedParam(p.name)} style={{ cursor: "pointer" }}>
           <td>
            <code>{p.name}</code>
           </td>
           <td>
            <Badge tone="neutral">{p.url_count}</Badge>
           </td>
          </tr>
         ))}
        </SimpleTable>
        {param ? (
         <div className="stack-tight">
          <span className="eyebrow">URLs taking {param.name}</span>
          {param.urls.map((u) => (
           <code key={u}>{u}</code>
          ))}
         </div>
        ) : (
         <small className="field-hint">Select a parameter to list the URLs that take it.</small>
        )}
       </>
      ) : (
       <Empty title="No parameters" detail="No captured request here carried a query or form parameter." />
      )
     ) : null}
    </>
   ) : null}
  </Card>
 );
}
