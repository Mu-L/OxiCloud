#!/usr/bin/env bash
# Boot a clean test DB then start OxiCloud serving the *SvelteKit* SPA
# (static-dist) for the coverage e2e suite. Mirrors start-server.sh but uses a
# separate storage dir so it can coexist with the legacy suite's state.
#
# The caller (playwright.coverage.config.ts) sets OXICLOUD_STATIC_PATH to
# ./static-dist so the debug `cargo run` build serves the instrumented Vite
# output instead of the legacy ./static vanilla frontend.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPA_STORAGE_PATH="$REPO_ROOT/tests/e2e/storage-spa"

# ensure storage is empty before starting
echo "Wipe $SPA_STORAGE_PATH to ensure clean startup"
rm -rf "$SPA_STORAGE_PATH"
mkdir -p "$SPA_STORAGE_PATH"

# Spawn database (idempotent — reuses the running test postgres if present).
bash "$REPO_ROOT/tests/common/spawn-db.sh"

# Replace the shell with the server process so Playwright's PID tracking works.
exec "$@"
