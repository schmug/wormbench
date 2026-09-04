#!/usr/bin/env bash
# Fast, offline checks; validates Compose without starting the benchmark.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python3 - <<'PY'
import ast
import json
from pathlib import Path

for root in (Path("judge"), Path("worm")):
    for path in sorted(root.rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        print(f"Python syntax OK: {path}")
for path in sorted(Path("worm").rglob("*.json")):
    json.loads(path.read_text(encoding="utf-8"))
    print(f"JSON OK: {path}")
PY

bash -n cli/wormbench ci/check.sh
sh -n victims/victim-2/entrypoint.sh
sh -n protections/clamav/report.sh

# Avoid loading a developer's local .env, and never print resolved config.
for override in compose-overrides/empty.yml protections/clamav/compose.yml; do
    docker compose --env-file .env.example -f docker-compose.yml -f "$override" config --quiet
    docker compose --env-file .env.example -f docker-compose.yml -f "$override" \
        -f .github/ci-ollama.yml config --quiet
done

git diff --check
echo "All fast checks passed."
