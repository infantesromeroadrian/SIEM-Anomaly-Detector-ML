#!/bin/sh
# Container entrypoint: make sure a model exists, then exec the requested command.
set -eu
MODEL_DIR="${MODEL_PATH:-/app/models}"
if [ -d "$MODEL_DIR" ] && ! ls "$MODEL_DIR"/ensemble_*.joblib >/dev/null 2>&1; then
    echo "WARNING: no model in $MODEL_DIR; training a synthetic DEMO model (not evaluated)." >&2
    python /app/scripts/train_demo_model.py --out "$MODEL_DIR"
fi
exec "$@"
