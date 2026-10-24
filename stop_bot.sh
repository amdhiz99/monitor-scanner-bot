#!/usr/bin/env bash
# Hentikan bot (dipanggil sebelum start ulang agar tidak 409 Conflict).
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$PROJECT_DIR/log/bot.pid"

if [ -f "$PID_FILE" ]; then
  PID="$(cat "$PID_FILE")"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    for _ in $(seq 1 10); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$PID" 2>/dev/null || true
    echo "Bot dihentikan (PID $PID)."
  else
    echo "PID $PID tidak aktif."
  fi
  rm -f "$PID_FILE"
else
  echo "Tidak ada pid file."
fi

# Bersihkan instance sisa
pkill -f "$PROJECT_DIR/bot.py" 2>/dev/null && echo "Instance sisa dihentikan." || true
