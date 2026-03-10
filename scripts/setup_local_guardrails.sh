#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
chmod +x .githooks/pre-push

echo "Local guardrails enabled."
echo "- hooksPath: .githooks"
echo "- pre-push: blocks direct main push and runs lint/tests"
