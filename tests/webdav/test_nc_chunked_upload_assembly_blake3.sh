#!/usr/bin/env bash
# =============================================================
# OxiCloud — Baseline: NC chunked-upload assembly + BLAKE3
# =============================================================
# Group J from BASELINE_TESTS_NC_WEBDAV.md.
#
# Headline assertion:
#   J7 — BLAKE3 round-trip on the ASSEMBLED file. Local b3sum
#        of `concat(chunk1, chunk2)` must equal the server's
#        FileDto.content_hash after the chunked-MOVE-to-`.file`
#        assembly step. Proves the streaming hash-on-write
#        during chunked assembly produces the canonical BLAKE3
#        — the same `content_hash` field that F8/F9 validate
#        for the direct-PUT path. F8/F9 + J7 together cover
#        every path a file's content_hash gets computed on.
#
# Scope split vs existing scripts:
#   - `test_nextcloud_chunked_upload_propfind.sh` already
#     covers J1-J4 (MKCOL session, PUT chunks, PROPFIND-resume).
#   - `test_nextcloud_chunked_upload_cap.sh` already covers
#     J8 (chunk-over-cap → 413).
#   - This script picks up the rest of the lifecycle:
#       J5 — MOVE `.file` to destination (assembly)
#       J6 — GET assembled file: bytes match concat
#       J7 — BLAKE3 round-trip on assembled (HEADLINE)
#       J9 — DELETE on a separate session (abort) → 204
#       J10 — PROPFIND on the J5 session AFTER assembly → 404
#
# `xq` is used for the J4-style PROPFIND assertions so the
# tests can XPath-query namespaced multistatus XML instead of
# parsing it with awk/sed. See the install line in
# `.github/workflows/ci.yml`.
# =============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source test.env
source common.sh
source lib/dav_helpers.sh

echo
echo "=== NC chunked-upload assembly + BLAKE3 (Group J baseline) ==="
echo

# Preflight: xq required for the multistatus XPath checks. Pinned to
# sibprogrammer/xq (Go binary, real XPath via libxml2).
command -v xq >/dev/null 2>&1 \
    || fail "preflight: xq required (sibprogrammer/xq) — install via 'brew install xq' or the CI release tarball"
command -v b3sum >/dev/null 2>&1 \
    || fail "preflight: b3sum required for the J7 round-trip — install via 'brew install b3sum' or 'apt install b3sum'"

oxicloud_login
mint_app_password
resolve_home_folder_id
wipe_home_folder

NC_FILES_BASE="$base_url/remote.php/dav/files/$username"
NC_UPLOAD_BASE="$base_url/remote.php/dav/uploads/$username"

FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"; \
      nc_curl -o /dev/null -X DELETE "$NC_FILES_BASE/j-assembled.bin" 2>/dev/null || true; \
      api_empty_trash                                                  2>/dev/null || true' EXIT

# ── Fixture: two chunks of known random content ──────────────────────────────
# 5 KB + 7 KB — sized to verify the assembly handles unequal-size
# chunks correctly (the wire ordering is by chunk number, not size).
CHUNK1_PATH="$FIXTURE_DIR/chunk1.bin"
CHUNK2_PATH="$FIXTURE_DIR/chunk2.bin"
ASSEMBLED_LOCAL="$FIXTURE_DIR/concat.bin"

dd if=/dev/urandom of="$CHUNK1_PATH" bs=1024 count=5 status=none
dd if=/dev/urandom of="$CHUNK2_PATH" bs=1024 count=7 status=none
cat "$CHUNK1_PATH" "$CHUNK2_PATH" > "$ASSEMBLED_LOCAL"

CHUNK1_LEN=$(wc -c < "$CHUNK1_PATH" | tr -d ' ')
CHUNK2_LEN=$(wc -c < "$CHUNK2_PATH" | tr -d ' ')
ASSEMBLED_LEN=$(wc -c < "$ASSEMBLED_LOCAL" | tr -d ' ')
ASSEMBLED_LOCAL_HASH=$(b3sum --no-names "$ASSEMBLED_LOCAL" | awk '{print $1}')

# Unique session id per run.
SESSION_ID="j-assembly-$(date +%s)-$$"
SESS_BASE="$NC_UPLOAD_BASE/$SESSION_ID"

# Defensive idempotent cleanup of any stale session from a previous run.
nc_curl -o /dev/null -X DELETE "$SESS_BASE" > /dev/null 2>&1 || true

# ─────────────────────────────────────────────────────────────
# Setup — Create the session and PUT both chunks. These mirror
# what the dedicated J1-J3 script does; we redo them so this
# file is self-contained for the assembly + BLAKE3 checks.
# ─────────────────────────────────────────────────────────────
echo "  setup: MKCOL session $SESSION_ID + PUT 2 chunks"

STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X MKCOL "$SESS_BASE")
[[ "$STATUS" == "201" ]] \
    || fail "setup: MKCOL expected 201, got $STATUS"

STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$CHUNK1_PATH" \
    "$SESS_BASE/00000001")
[[ "$STATUS" == "201" ]] \
    || fail "setup: PUT chunk 00000001 expected 201, got $STATUS"

STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$CHUNK2_PATH" \
    "$SESS_BASE/00000002")
[[ "$STATUS" == "201" ]] \
    || fail "setup: PUT chunk 00000002 expected 201, got $STATUS"

pass "setup: session created with 2 chunks ($CHUNK1_LEN + $CHUNK2_LEN bytes)"

# ─────────────────────────────────────────────────────────────
# J4-ish sanity check — PROPFIND the session via xq.
#
# We don't re-test J1-J3 in detail (covered by
# test_nextcloud_chunked_upload_propfind.sh), but a single
# PROPFIND-via-xq here gives us:
#   - early failure if the chunks didn't actually land
#   - smoke test that xq is operational in this environment
#     before J7 depends on it
# ─────────────────────────────────────────────────────────────
echo "  J4-sanity: PROPFIND session via xq → 3 <d:response> entries"
BODY=$(nc_curl -X PROPFIND -H "Depth: 1" "$SESS_BASE")
N=$(xq -x 'count(//*[local-name()="response"])' <<< "$BODY" | tr -d '\r\n ')
[[ "$N" == "3" ]] \
    || fail "J4-sanity: PROPFIND expected 3 responses, got '$N' (body: $BODY)"
# Confirm both chunk content-lengths are correct in the XML.
CHUNK1_REPORTED=$(xq -x "//*[local-name()='response'][.//*[local-name()='href' and contains(text(), '/00000001')]]//*[local-name()='getcontentlength']/text()" <<< "$BODY" | tr -d '\r\n ')
CHUNK2_REPORTED=$(xq -x "//*[local-name()='response'][.//*[local-name()='href' and contains(text(), '/00000002')]]//*[local-name()='getcontentlength']/text()" <<< "$BODY" | tr -d '\r\n ')
[[ "$CHUNK1_REPORTED" == "$CHUNK1_LEN" ]] \
    || fail "J4-sanity: chunk 00000001 reported $CHUNK1_REPORTED bytes, expected $CHUNK1_LEN"
[[ "$CHUNK2_REPORTED" == "$CHUNK2_LEN" ]] \
    || fail "J4-sanity: chunk 00000002 reported $CHUNK2_REPORTED bytes, expected $CHUNK2_LEN"
pass "J4-sanity: PROPFIND reports 3 responses + correct chunk sizes via xq"

# ─────────────────────────────────────────────────────────────
# J5 — MOVE `.file` to destination (assembly)
# ─────────────────────────────────────────────────────────────
echo "  J5: MOVE $SESSION_ID/.file → /j-assembled.bin"
HEADERS=$(nc_curl -D - -o /dev/null -X MOVE \
    -H "Destination: $NC_FILES_BASE/j-assembled.bin" \
    "$SESS_BASE/.file")
STATUS=$(awk 'NR==1{print $2}' <<< "$HEADERS" | tr -d '\r')
[[ "$STATUS" == "201" ]] \
    || fail "J5: assembly MOVE expected 201, got $STATUS"
# ETag + oc-etag headers should be present on the assembly response.
grep -qi '^etag:'    <<< "$HEADERS" \
    || fail "J5: assembly response missing ETag"
grep -qi '^oc-etag:' <<< "$HEADERS" \
    || fail "J5: assembly response missing oc-etag"
pass "J5: assembly MOVE → 201 + ETag/oc-etag headers"

# ─────────────────────────────────────────────────────────────
# J6 — GET assembled file: length + bytes match concatenation
# ─────────────────────────────────────────────────────────────
echo "  J6: GET assembled file matches local concat (bytes + length)"
ASSEMBLED_REMOTE="$FIXTURE_DIR/assembled-remote.bin"
nc_curl -o "$ASSEMBLED_REMOTE" "$NC_FILES_BASE/j-assembled.bin"
REMOTE_LEN=$(wc -c < "$ASSEMBLED_REMOTE" | tr -d ' ')
[[ "$REMOTE_LEN" == "$ASSEMBLED_LEN" ]] \
    || fail "J6: byte count mismatch — remote $REMOTE_LEN vs local $ASSEMBLED_LEN"
cmp -s "$ASSEMBLED_LOCAL" "$ASSEMBLED_REMOTE" \
    || fail "J6: assembled bytes differ from concat(chunk1, chunk2)"
pass "J6: assembled file is byte-identical to concat(chunk1, chunk2)"

# ─────────────────────────────────────────────────────────────
# J7 — BLAKE3 round-trip on assembled (HEADLINE)
#
# REST API exposes FileDto.content_hash (BLAKE3 hex) for every
# file row. The server computes this via hash-on-write during
# the chunked assembly path — same blake3::Hasher::update
# stream as the direct-PUT path, but driven by the chunk
# concatenation loop in
# `infrastructure/services/nextcloud_chunked_upload_service.rs::assemble`.
# Equality with the LOCAL b3sum of the same byte sequence
# proves the assembly path produces the canonical BLAKE3 the
# dedup / lifecycle hooks downstream key on.
# ─────────────────────────────────────────────────────────────
echo "  J7: BLAKE3 round-trip on assembled file (HEADLINE)"
# Find the assembled file's id via the REST `/resources` listing
# ({ items: [{ resource_type, resource }] }; `/listing` was removed).
listing=$(api_curl "$base_url/api/folders/$HOME_FOLDER_ID/resources?resource_types=file&limit=200")
ASSEMBLED_ID=$(jq -r '.items[]?.resource | select(.name == "j-assembled.bin") | .id'           <<< "$listing")
SERVER_HASH=$(jq -r '.items[]?.resource  | select(.name == "j-assembled.bin") | .content_hash' <<< "$listing")
[[ -n "$ASSEMBLED_ID" && "$ASSEMBLED_ID" != "null" ]] \
    || fail "J7: assembled file not visible via REST listing"
[[ -n "$SERVER_HASH"  && "$SERVER_HASH"  != "null" ]] \
    || fail "J7: REST listing returned empty content_hash for assembled file"
[[ "$SERVER_HASH" == "$ASSEMBLED_LOCAL_HASH" ]] \
    || fail "J7: BLAKE3 mismatch — server '$SERVER_HASH' vs local '$ASSEMBLED_LOCAL_HASH' (assembly hash-on-write regression?)"
pass "J7: assembled content_hash matches local b3sum ($ASSEMBLED_LOCAL_HASH)"

# ─────────────────────────────────────────────────────────────
# J10 — PROPFIND on the session AFTER assembly → 404
#
# Per the assembly contract, completing the MOVE to `.file`
# purges the session. A subsequent PROPFIND on the same
# session URL must return 404 (the resume-info is gone). If a
# regression starts returning 207 here, NC clients would
# loop-retry chunks against an already-assembled file.
# ─────────────────────────────────────────────────────────────
echo "  J10: PROPFIND on session AFTER assembly → 404"
STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X PROPFIND -H "Depth: 0" "$SESS_BASE")
[[ "$STATUS" == "404" ]] \
    || fail "J10: post-assembly PROPFIND expected 404, got $STATUS"
pass "J10: session purged after assembly (PROPFIND 404)"

# ─────────────────────────────────────────────────────────────
# J9 — DELETE on a FRESH session (abort path) → 204
# ─────────────────────────────────────────────────────────────
echo "  J9: DELETE on a fresh (un-assembled) session → 204"
ABORT_SESSION="j-abort-$(date +%s)-$$"
ABORT_BASE="$NC_UPLOAD_BASE/$ABORT_SESSION"

STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X MKCOL "$ABORT_BASE")
[[ "$STATUS" == "201" ]] \
    || fail "J9 setup: MKCOL expected 201, got $STATUS"
STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X PUT \
    --data-binary "@$CHUNK1_PATH" \
    "$ABORT_BASE/00000001")
[[ "$STATUS" == "201" ]] \
    || fail "J9 setup: PUT chunk expected 201, got $STATUS"

STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X DELETE "$ABORT_BASE")
[[ "$STATUS" == "204" ]] \
    || fail "J9: DELETE session expected 204, got $STATUS"

# Confirm it's gone.
STATUS=$(nc_curl -o /dev/null -w "%{http_code}" -X PROPFIND -H "Depth: 0" "$ABORT_BASE")
[[ "$STATUS" == "404" ]] \
    || fail "J9: PROPFIND after DELETE expected 404, got $STATUS"
pass "J9: aborted session DELETE → 204 + subsequent PROPFIND 404"

# ── Cleanup ──────────────────────────────────────────────────────────────────

echo "  cleanup"
nc_curl -o /dev/null -X DELETE "$NC_FILES_BASE/j-assembled.bin" || true
api_empty_trash || true
pass "cleanup done"

# ── summary ───────────────────────────────────────────────────────────────────

echo
echo "Results: $PASS passed, $FAIL failed."
[[ "$FAIL" -eq 0 ]] && echo "All tests passed." || exit 1
