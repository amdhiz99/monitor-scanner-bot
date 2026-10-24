#!/usr/bin/env bash
# Wrapper cron: muat environment lalu jalankan Modul A + Modul B berurutan.
# Semua output masuk log/cron.log (rotasi manual oleh logrotate bila perlu).

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR" || exit 1
mkdir -p log reports

# Pakai python sistem, bukan venv Hermes
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

# Muat .env bila ada (BOT_TOKEN / ADMIN_CHAT_ID menimpa config.json)
if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

{
  echo "===== $(date '+%Y-%m-%d %H:%M:%S %Z') mulai cron_scan ====="
} >> "$PROJECT_DIR/log/cron.log"

"$PYTHON_BIN" "$PROJECT_DIR/cron_scan.py" "$@" >> "$PROJECT_DIR/log/cron.log" 2>&1
STATUS=$?

echo "===== $(date '+%Y-%m-%d %H:%M:%S %Z') selesai (exit=$STATUS) =====" >> "$PROJECT_DIR/log/cron.log"
exit $STATUS
