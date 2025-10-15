#!/bin/bash
set -euo pipefail
export FRONTEND_DIR="${FRONTEND_DIR:-/workspace/frontend}"
python3 -m pip install -r /workspace/backend/requirements.txt
exec python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
