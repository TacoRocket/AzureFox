#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
chmod +x .githooks/pre-push

echo "Local guardrails enabled."
echo "- hooksPath: .githooks"
echo "- pre-push: validates branch naming, blocks direct main push, and runs lint/tests"
echo "- CI: validates PR titles so Codex-branded titles cannot slip into publish metadata"
