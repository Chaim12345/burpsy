#!/usr/bin/env python3
"""Give OWASP VulnerableApp's UnrestrictedFileUpload cases an upload the level accepts.

usage: vulnapp_upload_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON

The generated request list uploads test.txt (text/plain, "hello") to every level. Most levels accept
only an image - by name (".png"/".jpg"/".jpeg"), by declared type, or by the bytes' detected image
type (LEVEL_10 onwards) - so the captured upload is a refusal, nothing is stored, and the scanner's
upload check has no accepted baseline to vary or stored copy to fetch back. The app's own page
uploads a picture; this does the same with an inert 1x1 PNG named burpsy.png. The scanner replaces
the name, type and bytes with its own probes.

The multipart body is described, not built, here: {"multipart_file": field, "filename",
"content_type", "content_b64"}; full_benchmark.py builds it.

This is benchmark knowledge - the app's accepted image types - so it lives here and never in the
scanner. Nothing is sent to the application by this script.
"""
import base64
import json
import sys

FAMILY = "UnrestrictedFileUpload/"
# A valid 1x1 transparent PNG (67 bytes).
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def seed_entry(r):
    b = r.get("body") or {}
    if "multipart_file" not in b:
        return False
    b.update({"filename": "burpsy.png", "content_type": "image/png",
              "content_b64": base64.b64encode(PNG_1X1).decode()})
    r["body"] = b
    return True


def main():
    src, dst = sys.argv[1], sys.argv[2]
    reqs = json.load(open(src))
    n = 0
    for r in reqs:
        if r["test"].startswith(FAMILY):
            if seed_entry(r):
                n += 1
            else:
                print("%s: no multipart file part, left as generated" % r["test"], file=sys.stderr)
    json.dump(reqs, open(dst, "w"), indent=1)
    print("seeded %d upload case(s)" % n, file=sys.stderr)


if __name__ == "__main__":
    main()
