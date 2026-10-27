// Upload from URL with Add auth (burpsy-react-ui-fu4l): what the dialog sends and what it says.
import { describe, expect, test } from "bun:test";
import { blankFetchAuth, fetchAuthProblem, fetchedCaption, fetchedWarning, fetchRequestBody, fetchURLProblem } from "./apiscan-review";

describe("the definition URL", () => {
 test("must be an absolute http(s) URL with no credentials in it", () => {
  expect(fetchURLProblem("https://api.test/openapi.json")).toBeNull();
  expect(fetchURLProblem("")).toContain("empty");
  expect(fetchURLProblem("/openapi.json")).toContain("absolute");
  expect(fetchURLProblem("ftp://api.test/x")).toContain("http or https");
  expect(fetchURLProblem("https://alice:pw@api.test/x")).toContain("Add auth");
 });
});

describe("the auth method", () => {
 test("each method says what it is missing", () => {
  expect(fetchAuthProblem(blankFetchAuth("none"))).toBeNull();
  expect(fetchAuthProblem(blankFetchAuth("basic"))).toContain("username");
  expect(fetchAuthProblem(blankFetchAuth("bearer"))).toContain("token");
  expect(
   fetchAuthProblem({
    ...blankFetchAuth("oauth2_client_credentials"),
    type: "oauth2_client_credentials",
    tokenUrl: "",
    clientId: "app",
    clientSecret: "s",
    scope: "",
   }),
  ).toContain("token URL");
 });
});

describe("what Fetch posts", () => {
 test("no auth key at all for none, and the server's field names for the rest", () => {
  expect(fetchRequestBody(" https://a.test/spec ", { type: "none" })).toEqual({ url: "https://a.test/spec" });
  expect(fetchRequestBody("https://a.test/spec", { type: "basic", username: "alice", password: "p w" }).auth).toEqual({
   type: "basic",
   username: "alice",
   password: "p w",
  });
  expect(
   fetchRequestBody("https://a.test/spec", {
    type: "oauth2_client_credentials",
    tokenUrl: "https://a.test/token",
    clientId: "app",
    clientSecret: "sec",
    scope: "",
   }).auth,
  ).toEqual({ type: "oauth2_client_credentials", token_url: "https://a.test/token", client_id: "app", client_secret: "sec" });
 });
});

describe("what the dialog says about the result", () => {
 const base = { definition: "{}", url: "https://a.test/spec", status: 200, bytes: 2 };
 test("a readable definition is captioned with its format and no warning", () => {
  const fetched = { ...base, format: "openapi-3", scannable: true };
  expect(fetchedCaption(fetched)).toContain("OpenAPI 3");
  expect(fetchedWarning(fetched)).toBeNull();
 });
 test("a WSDL or unrecognised document is named, not passed off as scannable", () => {
  expect(fetchedWarning({ ...base, format: "wsdl", scannable: false, note: "SOAP" })).toContain("WSDL");
  expect(fetchedWarning({ ...base, format: "unknown", scannable: false, note: "an HTML page" })).toContain("an HTML page");
 });
});
