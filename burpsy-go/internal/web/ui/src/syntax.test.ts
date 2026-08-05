import { describe, expect, test } from "bun:test";
import { highlightAuto, highlightHttp } from "./syntax";

describe("syntax highlighting", () => {
  test("highlights an HTTP request without changing its content", () => {
    const html = highlightHttp("GET /admin?q=1 HTTP/1.1\r\nHost: target.test\r\n\r\n");
    expect(html).toContain('class="syn-method">GET</span>');
    expect(html).toContain('class="syn-target">/admin?q=1</span>');
    expect(html).toContain('class="syn-header">Host</span>');
  });

  test("highlights JSON response bodies", () => {
    const html = highlightHttp('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true,"count":2}');
    expect(html).toContain('class="syn-status">200</span>');
    expect(html).toContain('class="syn-key">&quot;ok&quot;</span>');
    expect(html).toContain('class="syn-number">2</span>');
  });

  test("escapes hostile captured markup", () => {
    const html = highlightAuto('<img src="x" onerror="alert(1)"><script>alert(2)</script>');
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;");
    expect(html).toContain('class="syn-attr">onerror</span>');
  });

  test("escapes plain text bodies", () => {
    const html = highlightHttp("HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>");
    expect(html).not.toContain("<script>");
    expect(html).toContain('class="syn-tag">script</span>');
  });
});
