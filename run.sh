#!/usr/bin/env bash
#
# run.sh — start the IMPACT II web app.
#
# Replaces typing the full uvicorn invocation. Picks up the project's .venv
# automatically, so it works whether or not the venv is activated.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

HOST="${IMPACT_HOST:-0.0.0.0}"
PORT="${IMPACT_PORT:-8000}"
RELOAD="${IMPACT_RELOAD:-true}"
EXTRA=()

usage() {
    cat <<'EOF'
Usage: ./run.sh [options] [-- extra uvicorn args]

  (no options)     dev server on 0.0.0.0:8000 with auto-reload
  --prod           production mode: no auto-reload
  --host HOST      bind address        (default 0.0.0.0, or $IMPACT_HOST)
  --port PORT      bind port           (default 8000,    or $IMPACT_PORT)
  -h, --help       show this message

Examples:
  ./run.sh
  ./run.sh --port 8080
  ./run.sh --prod
EOF
}

# `--host`/`--port` need a value; under `set -u` a missing one would otherwise
# fail with an unhelpful "unbound variable".
require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "run.sh: $1 requires a value" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prod)     RELOAD=false; shift ;;
        --host)     require_value "$@"; HOST="$2"; shift 2 ;;
        --port)     require_value "$@"; PORT="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        --)         shift; while [[ $# -gt 0 ]]; do EXTRA+=("$1"); shift; done ;;
        *)          EXTRA+=("$1"); shift ;;
    esac
done

# Prefer the project venv, then an activated one, then whatever python is on
# PATH — so this works without remembering to `source .venv/bin/activate`.
if [[ -x .venv/bin/python ]]; then
    PY=.venv/bin/python
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    PY="$VIRTUAL_ENV/bin/python"
else
    PY="$(command -v python3 || command -v python || true)"
fi

if [[ -z "$PY" ]]; then
    echo "run.sh: no python interpreter found" >&2
    exit 1
fi

if ! "$PY" -c "import uvicorn" >/dev/null 2>&1; then
    echo "run.sh: uvicorn is not installed for $PY" >&2
    echo "        try: $PY -m pip install -r requirements.txt" >&2
    exit 1
fi

ARGS=(main:app --host "$HOST" --port "$PORT")

# Load .env before the app is imported. The clients call load_dotenv() on
# import anyway, but that happens partway through main.py's own imports —
# loading it up front means every module sees the same environment.
if [[ -f .env ]]; then
    ARGS+=(--env-file .env)
fi

if [[ "$RELOAD" == "true" ]]; then
    ARGS+=(--reload)
fi

# ${EXTRA+...} guard: on macOS's bash 3.2, expanding an empty array under
# `set -u` is an error.
exec "$PY" -m uvicorn "${ARGS[@]}" ${EXTRA+"${EXTRA[@]}"}
