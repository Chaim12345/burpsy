#!/usr/bin/env bash
# review-verdict.sh REVIEWS.json COMMENTS.json — the latest valid agent-review verdict on a PR.
#
#   REVIEWS.json   the PR's reviews       (GET /repos/{o}/{r}/pulls/{n}/reviews, all pages, one array)
#   COMMENTS.json  the PR's issue comments (GET /repos/{o}/{r}/issues/{n}/comments, same)
#
# Prints one line: `approve <40-hex sha>`, `changes-required`, or `none`.
#
# A verdict is a line, alone on its line, in a review body or a comment body:
#     agent-review: approve <full 40-hex sha of the head the reviewer read>
#     agent-review: changes-required
# Counted only when the author's author_association is OWNER, MEMBER or COLLABORATOR — anyone else
# can comment on a public PR. A review is ignored when DISMISSED, and its approve counts only when the
# review's own commit_id is the sha in the marker (the review was submitted against that commit).
# Anything else — a short sha, extra words, a marker in a quote — is not a verdict. Several markers in
# one body: the last one counts. The latest verdict wins (reviews by submitted_at, comments by
# updated_at, so an edited comment counts as of its edit).
#
# Pure data in, one line out: jq parses the JSON; nothing from a body is evaluated.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 REVIEWS.json COMMENTS.json" >&2; exit 2; }

jq -r -n --slurpfile r "$1" --slurpfile c "$2" '
  def trusted: (.author_association // "") as $a | ["OWNER", "MEMBER", "COLLABORATOR"] | index($a) != null;
  def marker:
    [ (.body // "") | split("\n")[] | sub("\r$"; "")
      | capture("^agent-review: (?<v>approve (?<sha>[0-9a-f]{40})|changes-required)[ \t]*$") ]
    | last;
  ( [ ($r[0] // [])[]
      | select(type == "object" and trusted and (.state // "") != "DISMISSED")
      | . as $x | (marker) as $m | select($m != null)
      | select(($m.sha == null) or ($x.commit_id == $m.sha))
      | {t: ($x.submitted_at // ""), v: $m.v} ]
  + [ ($c[0] // [])[]
      | select(type == "object" and trusted)
      | . as $x | (marker) as $m | select($m != null)
      | {t: ($x.updated_at // $x.created_at // ""), v: $m.v} ] )
  | sort_by(.t) | last | if . == null then "none" else .v end
'
