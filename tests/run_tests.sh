#!/usr/bin/env bash
# Python is a development-test dependency, not an auditor runtime dependency.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null || { printf 'Tests require Python 3; RepoGuard itself does not.\n' >&2; exit 2; }
exec python3 run_tests.py
