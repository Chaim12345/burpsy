#!/usr/bin/env python3
"""Tests for run_vulnapp.py. Run: python3 scripts/bench/run_vulnapp_test.py"""
import http.server
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_vulnapp  # noqa: E402


class _RedirectAll(http.server.BaseHTTPRequestHandler):
    """Answers every request the way VulnerableApp's open-redirect LEVEL_6 answers a seed:
    a 302 whose Location is the request origin glued to the seed's own absolute-URL value -
    a string no HTTP client can open ("http://<host>:<port>https://example.org/")."""

    def do_GET(self):
        if self.path.endswith("returnTo=https%3A%2F%2Fexample.org%2F") or "returnTo=" in self.path:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1https://example.org/")
            self.end_headers()
            return
        # The followed redirect: mimic burpsy's proxy asked to open the unopenable Location -
        # the connection dies without a response (what urllib reports as RemoteDisconnected).
        self.connection.close()
        self.close_connection = True

    def log_message(self, *args):
        pass


class ProxiedThrough(unittest.TestCase):
    def test_seed_followed_by_unopenable_redirect_is_not_a_transport_failure(self):
        # Regression for burpsy-react-ui-j1mk.36: the default redirect-follow turned the app's
        # 302 answer into a connection error and the case scored untestable, though the seed
        # exchange had already been captured. proxied_through must treat the 302 as the answer.
        with http.server.HTTPServer(("127.0.0.1", 0), _RedirectAll) as server:
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # The stub stands in for both the proxy and the target: ProxyHandler sends it
                # the absolute-form request and it answers the 302 directly.
                run_vulnapp.proxied_through(
                    f"http://127.0.0.1:{port}", "http://127.0.0.1:1/seed?returnTo=https://example.org/"
                )
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
