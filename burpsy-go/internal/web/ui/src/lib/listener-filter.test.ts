import { describe, expect, test } from "bun:test";
import { parseListenerPorts } from "./listener-filter";

describe("the listener filter's port list", () => {
 test("is empty for an empty field, which means show every row", () => {
  expect(parseListenerPorts("").size).toBe(0);
  expect(parseListenerPorts("   ").size).toBe(0);
 });

 test("reads one port, and several", () => {
  expect([...parseListenerPorts("8080")]).toEqual([8080]);
  expect([...parseListenerPorts("8080,8443")].sort((a, b) => a - b)).toEqual([8080, 8443]);
 });

 test("normalises spacing and repeats, the way the extension lists do", () => {
  // " 8080 , 8080 " is one entry: an operator who typed a port twice means one port.
  expect([...parseListenerPorts(" 8080 , 8080 ")]).toEqual([8080]);
 });

 test("DROPS a non-numeric entry rather than coercing it to 0", () => {
  // The failure this rule exists for. Coercing "abc" to 0 would make the filter match every row
  // from a producer with no listener — Repeater, Intruder, a crawl — so the operator would see
  // traffic they did not ask for and conclude the filter is broken in the other direction.
  expect([...parseListenerPorts("abc")].sort()).toEqual([]);
  expect([...parseListenerPorts("8080,abc")]).toEqual([8080]);
  expect([...parseListenerPorts("-1")].sort()).toEqual([]);
 });

 test("keeps a port past 65535, because the column renders whatever the store recorded", () => {
  // Not this filter's job to second-guess the value; dropping it silently would hide rows the
  // operator can see in the column and wonder where they went.
  expect([...parseListenerPorts("99999")]).toEqual([99999]);
 });

 test("does not treat 0 as a listener", () => {
  // Zero is what a row with no listener carries, and offering it would be inventing a port. It is
  // not rejected here either — an operator who typed 0 asked for that value — but the PAGE never
  // offers 0 as a choice, so this only pins that the parse does not special-case it.
  expect([...parseListenerPorts("0")]).toEqual([0]);
 });
});
