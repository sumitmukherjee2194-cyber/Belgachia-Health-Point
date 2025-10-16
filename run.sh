#!/bin/bash
set -euo pipefail

# Load environment variables if present
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export FRONTEND_DIR="${FRONTEND_DIR:-/workspace/frontend}"
export UPLOAD_DIR="${UPLOAD_DIR:-/workspace/backend/uploads}"

python3 -m pip install -r /workspace/backend/requirements.txt
exec python3 -m uvicorn backend.app:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
