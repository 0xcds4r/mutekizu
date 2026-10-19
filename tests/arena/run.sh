#!/usr/bin/env bash
# Reproducible entry point for the isolated arena.
#   tests/arena/run.sh [arena.py options]
set -euo pipefail
cd "$(dirname "$0")/../.."
exec unshare -rn python3 tests/arena/arena.py "$@"
