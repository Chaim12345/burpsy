#!/usr/bin/env python3
"""
Script to parse open beads issues from .beads/issues.jsonl and create
corresponding GitHub issues if GITHUB_TOKEN / GH_TOKEN environment variable is set.
If no token is provided, prints a summary and exports OPEN_ISSUES.md.
"""

import json
import os
import sys
import urllib.error
import urllib.request

BEADS_FILE = ".beads/issues.jsonl"
OUTPUT_MD = "OPEN_ISSUES.md"
REPO_OWNER = "Chaim12345"
REPO_NAME = "burpsy"


def load_open_issues():
    if not os.path.exists(BEADS_FILE):
        print(f"Error: {BEADS_FILE} not found.", file=sys.stderr)
        sys.exit(1)

    open_issues = []
    with open(BEADS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if item.get("status") == "open":
                open_issues.append(item)

    open_issues.sort(key=lambda x: (x.get("priority", 99), x.get("id", "")))
    return open_issues


def format_body(issue):
    body = []
    body.append(f"**Beads ID:** `{issue.get('id')}`")
    body.append(f"**Priority:** P{issue.get('priority', 'N/A')}")

    labels = issue.get("labels", [])
    if labels:
        body.append(f"**Labels:** {', '.join(labels)}")

    body.append("\n### Description\n")
    body.append(issue.get("description", "No description provided."))

    criteria = issue.get("acceptance_criteria")
    if criteria:
        body.append("\n### Acceptance Criteria\n")
        body.append(criteria)

    return "\n".join(body)


def create_github_issue(token, issue):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues"
    title = f"[{issue.get('id')}] {issue.get('title')}"
    payload = {
        "title": title,
        "body": format_body(issue),
        "labels": issue.get("labels", []),
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "burpsy-beads-exporter",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"Created issue #{data.get('number')}: {title} ({data.get('html_url')})")
            return True
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"Failed to create issue for {issue.get('id')}: {e.code} {e.reason}\n{err_msg}", file=sys.stderr)
        return False


def main():
    open_issues = load_open_issues()
    print(f"Found {len(open_issues)} open issues in {BEADS_FILE}.\n")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if token:
        print("GitHub token detected. Creating issues on GitHub...")
        success = 0
        for issue in open_issues:
            if create_github_issue(token, issue):
                success += 1
        print(f"\nSuccessfully created {success}/{len(open_issues)} GitHub issues.")
    else:
        print("No GITHUB_TOKEN or GH_TOKEN set in environment.")
        print(f"Generating {OUTPUT_MD} with open issue details...\n")

        md_content = ["# Open Beads Issues\n"]
        for issue in open_issues:
            md_content.append(f"## [{issue.get('id')}] {issue.get('title')}\n")
            md_content.append(format_body(issue))
            md_content.append("\n---\n")

        with open(OUTPUT_MD, "w", encoding="utf-8") as f:
            f.write("\n".join(md_content))

        print(f"Exported {len(open_issues)} open issues to {OUTPUT_MD}.")
        print("\nTo push issues to GitHub directly, run:")
        print("  GITHUB_TOKEN=<your_token> python3 scripts/export_beads_to_github_issues.py")


if __name__ == "__main__":
    main()
