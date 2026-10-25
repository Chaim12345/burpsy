// Burp's GraphQL context actions on an editable request (burpsy-react-ui-7v1e): "Set introspection
// query" and "Set legacy introspection query" (desktop/testing-workflow/working-with-graphql.html).
//
// The two documents are Burp's own, byte for byte, from burp.Zu6 in the decompiled 2026.7.1 jar —
// not recalled text and not the crawler's deliberately cut-down probe (internal/crawler/graphql.go),
// which asks for names only. The legacy variant drops subscriptionType and replaces directive
// `locations` with the pre-2016 onOperation/onFragment/onField flags, for servers too old to know
// the newer fields.
import { addHeader, headerValue, parseMessage, setBody } from "./message";

/** burp.Zu6 "Set introspection query". */
export const INTROSPECTION_QUERY =
 "query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        subscriptionType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            locations\n            args {\n                ...InputValue\n            }\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}";

/** burp.Zu6 "Set legacy introspection query". */
export const LEGACY_INTROSPECTION_QUERY =
 "query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            args {\n                ...InputValue\n            }\n            onOperation\n            onFragment\n            onField\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}";

/** Where a request carries its GraphQL query. */
export type GraphQLPlacement = "body" | "url";

/** The JSON body as an object, or null when the body is not a JSON object. */
function jsonBody(raw: string): Record<string, unknown> | null {
 const body = parseMessage(raw).body.trim();
 if (!body.startsWith("{")) return null;
 try {
  const parsed: unknown = JSON.parse(body);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
 } catch {
  return null;
 }
}

/** The request target's query parameters, or null when the start line has no target. */
function targetOf(raw: string): { start: number; end: number; target: string } | null {
 const lineEnd = raw.search(/\r?\n/);
 const line = lineEnd < 0 ? raw : raw.slice(0, lineEnd);
 const first = line.indexOf(" ");
 const last = line.lastIndexOf(" ");
 if (first < 0 || last <= first) return null;
 return { start: first + 1, end: last, target: line.slice(first + 1, last) };
}

/**
 * Where this request's query lives: a JSON body with a `query` member, else a `query` URL parameter,
 * else — for a request carrying it nowhere — the URL for a GET and a JSON body for anything else.
 */
export function graphqlPlacement(raw: string): GraphQLPlacement {
 const body = jsonBody(raw);
 if (body && "query" in body) return "body";
 const target = targetOf(raw);
 if (target && new URLSearchParams(target.target.split("?")[1] ?? "").has("query")) return "url";
 const method = (target ? raw.slice(0, target.start - 1) : "").toUpperCase();
 return method === "GET" || method === "HEAD" ? "url" : "body";
}

/**
 * Replace the request's GraphQL query with `query`, in the place the request already carries it, and
 * clear its variables — an introspection document declares none, and stale variables for the
 * previous operation make some servers refuse the request. An operationName that named the previous
 * operation is set to the new document's. Every header and the start line's method and version are
 * kept; a body edit recomputes Content-Length.
 */
export function setGraphQLQuery(raw: string, query: string): string {
 const placement = graphqlPlacement(raw);
 if (placement === "body") {
  const body = jsonBody(raw) ?? {};
  const next: Record<string, unknown> = { ...body, query, variables: {} };
  if ("operationName" in body) next.operationName = "IntrospectionQuery";
  const typed =
   headerValue(parseMessage(raw).headers, "content-type") === undefined ? addHeader(raw, "Content-Type", "application/json") : raw;
  return setBody(typed, JSON.stringify(next));
 }
 const target = targetOf(raw);
 if (!target) return raw;
 const [path, search = ""] = target.target.split("?", 2) as [string, string?];
 const params = new URLSearchParams(search);
 params.set("query", query);
 if (params.has("variables")) params.set("variables", "{}");
 if (params.has("operationName")) params.set("operationName", "IntrospectionQuery");
 return raw.slice(0, target.start) + `${path}?${params.toString()}` + raw.slice(target.end);
}

/** Whether a response body is an introspection answer — what enables "Save GraphQL queries to site map". */
export function isIntrospectionAnswer(raw: string): boolean {
 try {
  const parsed = JSON.parse(parseMessage(raw).body.trim()) as { data?: { __schema?: unknown } };
  return parsed?.data?.__schema != null;
 } catch {
  return false;
 }
}
