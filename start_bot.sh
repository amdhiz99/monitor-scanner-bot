#!/usr/bin/env bash
# Jalankan bot di background. Hentikan dengan ./stop_bot.sh
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR" || exit 1
mkdir -p log reports

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
PID_FILE="$PROJECT_DIR/log/bot.pid"
LOG_FILE="$PROJECT_DIR/log/bot_stdout.log"

if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

# Sudah jalan? (polling ganda menyebabkan error 409 Conflict)
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE")"
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Bot sudah berjalan (PID $OLD_PID). Hentikan dulu: ./stop_bot.sh"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

# Instance yatim tanpa pid file
if pgrep -f "python3 $PROJECT_DIR/bot.py" >/dev/null 2>&1; then
  echo "Ditemukan instance bot lain (tanpa pid file). Hentikan dulu: ./stop_bot.sh"
  exit 1
fi

nohup "$PYTHON_BIN" "$PROJECT_DIR/bot.py" >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Bot berjalan (PID $(cat "$PID_FILE")). Log: $LOG_FILE"
else
  echo "Bot gagal start. Cek $LOG_FILE"
  rm -f "$PID_FILE"
  exit 1
fi
