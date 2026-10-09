import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, json } from "../lib/api";
import { LoadingPanel, RefreshButton, SectionHeading } from "../ui/layout";
import { Button, Card, ErrorNotice, Input } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/** GET/PUT /api/project/logging — Burp's Project settings → Logging (burpsy-react-ui-nvfl). */
interface FileLoggingState {
  requests: Record<string, string>;
  responses: Record<string, string>;
  tools: string[];
  stats: { written: number; dropped: number; last_error?: string };
}

const TOOL_LABELS: Record<string, string> = {
  all_tools: "All tools",
  proxy: "Proxy",
  scanner: "Scanner (crawl and audit)",
  repeater: "Repeater",
  intruder: "Intruder",
  sequencer: "Sequencer",
  extender: "Extensions",
};

/**
 * Which tools append their requests and responses to which files. A path is a file on the machine
 * burpsy runs on, written by the server process; blank is off, Burp's default for every tool.
 */
export function FileLoggingSection(): JSX.Element {
  const client = useQueryClient();
  const { data, error, isFetching, isLoading, refetch } = useQuery({
    queryKey: ["project", "logging"],
    queryFn: ({ signal }) => api<FileLoggingState>("/api/project/logging", { signal }),
  });
  const save = useMutation({
    mutationFn: (body: { requests: Record<string, string>; responses: Record<string, string> }) =>
      api<FileLoggingState>("/api/project/logging", json("PUT", body)),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["project", "logging"] }),
  });
  const [requests, setRequests] = useState<Record<string, string>>({});
  const [responses, setResponses] = useState<Record<string, string>>({});
  useEffect(() => {
    if (data) {
      setRequests(data.requests);
      setResponses(data.responses);
    }
  }, [data]);
  const tools = data?.tools ?? [];
  const dirty = data !== undefined && (JSON.stringify(requests) !== JSON.stringify(data.requests) || JSON.stringify(responses) !== JSON.stringify(data.responses));

  return (
    <Card>
      <SectionHeading
        title="Logging"
        detail="Append each tool's requests, responses, or both to a file as they happen, in Burp's log-file format. A path is an absolute file path on the machine burpsy runs on; blank is off. The files receive raw messages, cookies and Authorization headers included."
        actions={
          <>
            <Button
              size="small"
              disabled={!dirty || save.isPending}
              onClick={() =>
                save.mutate(
                  { requests, responses },
                  {
                    onSuccess: () => toast.success("Logging settings applied"),
                    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Logging settings were refused"),
                  },
                )
              }
            >
              Save
            </Button>
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading logging settings" /> : null}
      {tools.length > 0 ? (
        <SimpleTable headers={["Tool", "Requests file", "Responses file"]}>
          {tools.map((tool) => (
            <tr key={tool}>
              <td>{TOOL_LABELS[tool] ?? tool}</td>
              <td>
                <Input
                  aria-label={`${TOOL_LABELS[tool] ?? tool} requests file`}
                  placeholder="off"
                  value={requests[tool] ?? ""}
                  onChange={(event) => setRequests({ ...requests, [tool]: event.target.value })}
                />
              </td>
              <td>
                <Input
                  aria-label={`${TOOL_LABELS[tool] ?? tool} responses file`}
                  placeholder="off"
                  value={responses[tool] ?? ""}
                  onChange={(event) => setResponses({ ...responses, [tool]: event.target.value })}
                />
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
      {data ? (
        <p className="field-hint">
          {data.stats.written} entr{data.stats.written === 1 ? "y" : "ies"} written this session
          {data.stats.dropped > 0 ? `, ${data.stats.dropped} dropped because the writer fell behind` : ""}
          {data.stats.last_error ? `. Last write error: ${data.stats.last_error}` : "."} Traffic this build does
          not attribute to a tool (Sequencer and extension sends among it) is not logged, under All tools either.
        </p>
      ) : null}
    </Card>
  );
}
