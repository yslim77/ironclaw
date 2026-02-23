#!/usr/bin/env bash
set -euo pipefail

# Lightweight staged-diff secret scan as a defense-in-depth layer on top of
# detect-secrets. We only inspect added lines to reduce noise.
DIFF_CONTENT="$(git diff --cached -U0 --no-color || true)"
if [[ -z "${DIFF_CONTENT}" ]]; then
  exit 0
fi

matches="$(
  printf '%s\n' "$DIFF_CONTENT" \
    | rg -n --no-line-number \
      '^\+.*(sk-[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})' \
      || true
)"

if [[ -n "${matches}" ]]; then
  echo "Potential secret detected in staged changes." >&2
  echo "Review the added lines below, rotate if needed, and use managed secret references." >&2
  printf '%s\n' "${matches}" >&2
  exit 1
fi

exit 0
