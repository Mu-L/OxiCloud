#!/usr/bin/env bash
# Interactive Playwright codegen driver (invoked by `just front-codegen`).
#
# Pick a starting-point recorder from scenarios/codegen/, record against a
# throwaway container stack, then turn the recording into a real spec:
#   record → name (re-prompts until free) → $EDITOR paste → assemble → run →
#   reopen in --debug on failure.
set -euo pipefail

# Run from tests/e2e regardless of how we were invoked.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Pick a recorder (menu of scenarios/codegen/*.spec.ts) ─────────────────────
shopt -s nullglob
files=(scenarios/codegen/*.spec.ts)
[[ ${#files[@]} -gt 0 ]] || { echo "no recorder files in scenarios/codegen/" >&2; exit 1; }
names=()
for f in "${files[@]}"; do names+=("$(basename "$f" .spec.ts)"); done
echo "Pick a codegen starting point:"
PS3="› "
select n in "${names[@]}"; do [[ -n "${n:-}" ]] && break; echo "  invalid choice — enter a number"; done
echo "→ recorder: $n"

# ── Environment ───────────────────────────────────────────────────────────────
# NixOS (and distros where Playwright's bundled chromium can't run) need a
# system chromium. Respect an explicit PW_CHROMIUM_PATH, else auto-detect.
chromium="${PW_CHROMIUM_PATH:-$(command -v chromium 2>/dev/null || true)}"
if [[ -n "$chromium" ]]; then export PW_CHROMIUM_PATH="$chromium"; echo "→ chromium: $chromium"; fi
# Build the app image from the CURRENT source for codegen, so recordings reflect
# the latest frontend (and its data-testid hooks) instead of a stale image.
#
# We build it HERE with the buildx CLI rather than letting the Testcontainers
# fixture build it. The fixture's JS-driven BuildKit build does NOT reuse the
# local cargo cache mounts, so it cold-compiles the whole binary every run
# (>5 min) and blows past the 200 s stack-setup timeout. The CLI build uses the
# `builder-cache` stage and the shared cache mounts, so it recompiles only what
# changed (seconds on a warm cache); we then hand the tag to the fixture via
# $OXICLOUD_IMAGE, which makes it skip its own build entirely.
#
# Escape hatch: export OXICLOUD_IMAGE yourself to force-reuse a prebuilt image
# (it must be built with --build-arg VITE_E2E=1, and may be stale vs local edits).
if [[ -n "${OXICLOUD_IMAGE:-}" ]]; then
  echo "→ OXICLOUD_IMAGE=$OXICLOUD_IMAGE (env override) — reusing it; needs VITE_E2E=1 and may be stale."
else
  REPO_ROOT="$(cd ../.. && pwd)"
  OXICLOUD_IMAGE="oxicloud-e2e:latest"
  echo "→ building $OXICLOUD_IMAGE from current source (buildx, incremental — only changed crates/assets recompile)…"
  DOCKER_BUILDKIT=1 docker build \
    --build-arg BUILDER=builder-cache \
    --build-arg BIN_DIR=/app/bin \
    --build-arg VITE_E2E=1 \
    --tag "$OXICLOUD_IMAGE" \
    "$REPO_ROOT"
  export OXICLOUD_IMAGE
  echo "→ OXICLOUD_IMAGE=$OXICLOUD_IMAGE (prebuilt; fixture will reuse it)"
fi
export OXICLOUD_E2E_CONTAINERS=1

# ── Record ────────────────────────────────────────────────────────────────────
npx playwright test -c playwright.codegen.config.ts "scenarios/codegen/$n.spec.ts" --headed --workers=1

# ── Save the recording as a real spec ─────────────────────────────────────────
# Keeps the template's setup (apiLogin/goto), drops page.pause(), and splices in
# the steps you paste (handles a full codegen file or bare action lines).
echo
# Prompt for a spec name until it's valid and not already taken (blank = skip).
spec=""
while :; do
  read -rp "Save recording to a spec? Enter a name (blank to skip): " out || true
  [[ -z "${out:-}" ]] && break
  spec="$(node scripts/finish-codegen.mjs --resolve "$out")" && break || true
done
[[ -n "$spec" ]] || exit 0

# Collect the recording in $VISUAL/$EDITOR (paste, then save & close). For GUI
# editors set a blocking flag, e.g. EDITOR="code --wait". Falls back to nano/vi,
# then to a Ctrl-D paste if no editor is available.
editor="${VISUAL:-${EDITOR:-}}"
[[ -z "$editor" ]] && editor="$(command -v nano 2>/dev/null || command -v vi 2>/dev/null || true)"
tmp="$(mktemp --suffix=.recording.ts)"
trap 'rm -f "$tmp"' EXIT
if [[ -n "$editor" ]]; then
  echo "Opening $editor — paste the recorded output, then save & close."
  $editor "$tmp"
  recording="$(cat "$tmp")"
else
  echo "No \$VISUAL/\$EDITOR set. Paste the recorded output, then press Ctrl-D:"
  recording="$(cat)"
fi

if [[ -z "${recording//[[:space:]]/}" ]]; then
  echo "(empty — nothing saved)"
  exit 0
fi

printf '%s' "$recording" | node scripts/finish-codegen.mjs "scenarios/codegen/$n.spec.ts" "$out" >/dev/null

# ── Run the new spec; reopen in --debug on failure ────────────────────────────
echo "→ running $spec"
if npx playwright test -c playwright.containers.config.ts "$spec" --workers=1; then
  echo "✓ $spec passed"
else
  echo "✗ $spec failed — reopening in debug mode…"
  npx playwright test -c playwright.containers.config.ts "$spec" --workers=1 --debug
fi
