#!/usr/bin/env python3
"""crawlfix.py — the WIVET-style crawl-coverage fixture (j1mk.27).

A tiny stdlib HTTP app whose whole point is its LINK GRAPH: every page a complete crawler can
reach from the index, each exposed through a different discovery mechanism, plus the traps a
crawler must NOT turn into locations (fragment-only, mailto:, out-of-scope). TRUTH declares the
reachable set with the mechanism that exposes it, so the parity class (parity_specs
"crawl-coverage") has ground truth and crawlfix_test.py keeps this table and the spec's copy the
same fact. WIVET (sourceforge.net/projects/wivet) is the inspiration, not the source: it is a
PHP app last released in 2015, and a fixture we declare is a fixture we can check.

Two loopback binds, one port: 127.0.0.1 serves the app; 127.0.0.2 serves ONLY /outside — the
scope trap must be fetchable-if-tried so that not fetching it is a crawler's scope decision,
never a connection failure (127.0.0.0/8 is all loopback on Linux).

  python3 scripts/bench/crawlfix.py [-addr 127.0.0.1:19091]
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The reachable set, one row per URL, with the mechanism that exposes it. This table is the
# fixture's half of the ground-truth contract; parity_specs.CLASSES["crawl-coverage"]["truth"]
# is the other half, and crawlfix_test.py's test_spec_truth_matches_the_fixture_declaration
# fails the moment they drift.
TRUTH = [
    {"path": "/", "mechanism": "seed"},
    {"path": "/a", "mechanism": "href"},
    {"path": "/b", "mechanism": "href-relative"},
    {"path": "/abs", "mechanism": "href-absolute"},
    {"path": "/a/child", "mechanism": "href-depth-2"},
    {"path": "/search", "mechanism": "form-action-get"},
    {"path": "/submit", "mechanism": "form-action-post"},
    {"path": "/b/next", "mechanism": "form-action-depth-2"},
    {"path": "/meta", "mechanism": "meta-refresh"},
    {"path": "/comment-link", "mechanism": "html-comment"},
    {"path": "/js-inline", "mechanism": "js-inline-string"},
    {"path": "/js-rendered", "mechanism": "js-dom-append"},
    {"path": "/robots.txt", "mechanism": "known-file"},
    {"path": "/robots-only", "mechanism": "robots-disallow"},
    {"path": "/sitemap.xml", "mechanism": "robots-sitemap-directive"},
    {"path": "/sitemap-only", "mechanism": "sitemap"},
]

_LEAF = "<!DOCTYPE html><html><body><h1>{title}</h1><a href=\"/\">home</a></body></html>"

# The index carries every mechanism. {self} and {outside} are filled per request so the fixture
# is port-agnostic.
_INDEX = """<!DOCTYPE html><html><head>
<meta http-equiv="refresh" content="0; url=/meta">
</head><body>
<h1>crawlfix</h1>
<a href="/a">plain href</a>
<a href="b">relative href</a>
<a href="@SELF@/abs">absolute href</a>
<a href="#section">fragment only, not a location</a>
<a href="mailto:archive@example.invalid">mailto, not http</a>
<a href="@OUTSIDE@/outside">out of scope sibling loopback</a>
<form action="/search" method="get"><input type="text" name="q"><button>go</button></form>
<form action="/submit" method="post"><input type="text" name="name"><input type="text" name="token"><button>send</button></form>
<!-- the archived export moved to /comment-link -->
<script>var nextPage = "/js-inline";</script>
<script>
document.addEventListener("DOMContentLoaded", function () {
  var a = document.createElement("a");
  a.href = "/js-rendered";
  a.textContent = "rendered link";
  document.body.appendChild(a);
});
</script>
</body></html>"""

_A = ("<!DOCTYPE html><html><body><h1>a</h1>"
      "<a href=\"/a/child\">child</a><a href=\"/\">home</a></body></html>")

_B = ("<!DOCTYPE html><html><body><h1>b</h1>"
      "<form action=\"/b/next\" method=\"get\"><input type=\"text\" name=\"c\">"
      "<button>go</button></form><a href=\"/\">home</a></body></html>")

_ROBOTS = "User-agent: *\nDisallow: /robots-only\nSitemap: {self}/sitemap.xml\n"

_SITEMAP = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
            "<url><loc>{self}/sitemap-only</loc></url>\n"
            "</urlset>\n")


def _page(path, self_url, outside_url):
    if path == "/":
        return "text/html", _INDEX.replace("@SELF@", self_url).replace("@OUTSIDE@", outside_url)
    if path == "/a":
        return "text/html", _A
    if path == "/b":
        return "text/html", _B
    if path == "/robots.txt":
        return "text/plain", _ROBOTS.replace("{self}", self_url)
    if path == "/sitemap.xml":
        return "application/xml", _SITEMAP.replace("{self}", self_url)
    if path == "/truth.json":
        return "application/json", json.dumps(TRUTH, indent=1)
    if path == "/outside":
        return "text/html", _LEAF.format(title="outside the engagement scope")
    leaves = {"/a/child", "/abs", "/search", "/submit", "/b/next", "/meta", "/comment-link",
              "/js-inline", "/js-rendered", "/robots-only", "/sitemap-only"}
    if path in leaves:
        return "text/html", _LEAF.format(title=path)
    return None


class _Handler(BaseHTTPRequestHandler):
    def _respond(self):
        port = self.server.server_address[1]
        body = _page(self.path.split("?")[0].split("#")[0],
                     f"http://127.0.0.1:{port}", f"http://127.0.0.2:{port}")
        if body is None:
            self.send_error(404)
            return
        ctype, text = body
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _respond

    def log_message(self, *args):  # the nightly log stays readable
        pass


class Fixture:
    """Both binds on one port; server_address/shutdown/server_close read like one server."""

    def __init__(self, host, port):
        self.main = ThreadingHTTPServer((host, port), _Handler)
        got = self.main.server_address[1]
        self.sibling = ThreadingHTTPServer(("127.0.0.2", got), _Handler)
        self.server_address = self.main.server_address
        self._threads = [threading.Thread(target=s.serve_forever, daemon=True)
                         for s in (self.main, self.sibling)]
        for t in self._threads:
            t.start()

    def shutdown(self):
        for s in (self.main, self.sibling):
            s.shutdown()

    def server_close(self):
        for s in (self.main, self.sibling):
            s.server_close()


def serve(host, port):
    return Fixture(host, port)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-addr", default="127.0.0.1:19091")
    a = ap.parse_args()
    host, _, port = a.addr.rpartition(":")
    fx = serve(host, int(port))
    print(f"crawlfix on http://{host}:{fx.server_address[1]} (scope trap on 127.0.0.2)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        fx.shutdown()


if __name__ == "__main__":
    main()
