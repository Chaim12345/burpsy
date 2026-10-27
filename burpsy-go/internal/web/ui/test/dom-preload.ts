// Registers a DOM (happy-dom) for the component tests: `bun run test:components`. The lib tests
// run without it on purpose, so a lib module that quietly depends on `document` fails there.
import { GlobalRegistrator } from "@happy-dom/global-registrator";

if (typeof document === "undefined") GlobalRegistrator.register({ url: "http://localhost/" });
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// No test talks to a server: any request a component makes settles at once as a 404.
globalThis.fetch = (async () =>
 new Response("{}", { status: 404, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;

// Isolation: the component tests share one process, so one store and one localStorage. Reset both
// after every test so a preference a test turns on (urlEncodeAsYouType, hidden headers, a theme, open
// tabs) cannot change a later test in another file. src/ui/test-isolation.test.tsx pins this.
const { afterEach } = await import("bun:test");
const { useApp } = await import("../src/lib/store");
afterEach(() => {
 useApp.setState(useApp.getInitialState(), true);
 window.localStorage.clear();
});
