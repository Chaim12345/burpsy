/**
 * Rendered-evidence harness for the 1944 correction round's UI half (screenshots for review).
 * Mounts the real RepeaterPage in a browser with a mocked fetch and drives the three states
 * Main asked to see rendered: ?scenario=failure | retried | empty-last-tab.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { createRoot } from "react-dom/client";
import { RepeaterPage } from "../src/pages/repeater";
import { useApp } from "../src/lib/store";
import { forgetRepeaterTabAction } from "../src/lib/data";
import { useThemeEffect } from "../src/lib/use-theme-effect";

const scenario = new URLSearchParams(window.location.search).get("scenario") ?? "failure";
let deleteStatuses: number[] =
 scenario === "retried" ? [500, 200] : [500];

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
 const url = new URL(String(input), window.location.origin);
 const method = (init?.method ?? "GET").toUpperCase();
 if (url.pathname === "/api/repeater/tabs/confirm") {
  return new Response(
   JSON.stringify({ token: "tok-1", binding: "b1", call: { method: "DELETE", url: "/", body_bytes: 0, body_sha256: "x", body_kind: "none" }, expires_in: 60 }),
   { status: 200, headers: { "content-type": "application/json" } },
  );
 }
 if (method === "DELETE" && url.pathname.endsWith("/action")) {
  const status = deleteStatuses.length > 1 ? deleteStatuses.shift()! : deleteStatuses[0]!;
  return new Response(status === 200 ? "{}" : "the action store is unavailable", {
   status,
   headers: { "content-type": "application/json" },
  });
 }
 if (method === "GET" && (url.pathname.endsWith("/connections") || url.pathname.endsWith("/history") || url.pathname.endsWith("/tabs"))) {
  return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
 }
 return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
}) as typeof fetch;

window.localStorage.clear();
const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity }, mutations: { retry: false } } });

const id = useApp.getState().openRepeaterTab({ name: "login-flow", target: "https://target.test:443", request: "POST /login HTTP/1.1\r\nHost: target.test\r\n\r\n" });

function Harness(): JSX.Element {
 useThemeEffect();
 return (
  <QueryClientProvider client={client}>
   <TooltipPrimitive.Provider>
    <RepeaterPage />
   </TooltipPrimitive.Provider>
  </QueryClientProvider>
 );
}

createRoot(document.getElementById("root")!).render(<Harness />);

// Drive the scenario after the page has mounted. Virtual time in headless Chrome fast-forwards
// these timers; the screenshot lands after the last one.
setTimeout(() => {
 if (scenario === "failure") {
  forgetRepeaterTabAction(id);
 } else if (scenario === "empty-last-tab") {
  useApp.getState().closeRepeaterTab(id);
  forgetRepeaterTabAction(id);
 } else if (scenario === "retried") {
  forgetRepeaterTabAction(id); // 500: the failure notice appears first
  setTimeout(() => {
   forgetRepeaterTabAction(id); // what the Retry button calls: 200 this time
  }, 800);
 }
}, 800);
