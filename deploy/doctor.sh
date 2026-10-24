#!/usr/bin/env bash
# Diagnosa cepat instalasi scanner di server.
#
#   ./deploy/doctor.sh                 # periksa semua (tidak mengirim pesan)
#   ./deploy/doctor.sh --send          # sekalian kirim 1 pesan uji ke Telegram
#   APP_DIR=~/tools/monitor-scanner-bot ./deploy/doctor.sh
#
set -uo pipefail

APP_DIR="${APP_DIR:-/opt/scanner-bot}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SEND=0
[ "${1:-}" = "--send" ] && SEND=1

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
FAILS=0
fail() { bad "$1"; FAILS=$((FAILS+1)); }

step "Lokasi"
if [ -f "$APP_DIR/bot.py" ]; then ok "kode di $APP_DIR"
else fail "kode tidak ditemukan di $APP_DIR (set APP_DIR=...)"; exit 1; fi
echo "  systemd unit : $(systemctl show -p FragmentPath --value scanner-bot 2>/dev/null || echo '?')"
echo "  cron         : $(ls /etc/cron.d/scanner-bot 2>/dev/null || echo 'tidak ada')"

step "Python & dependensi"
if "$PYTHON_BIN" -c 'import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)' 2>/dev/null; then
  ok "$PYTHON_BIN $("$PYTHON_BIN" -V 2>&1 | awk '{print $2}')"
else fail "python3 < 3.8 di $PYTHON_BIN"; fi
for t in openssl ss nmap nuclei; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t ada"; else warn "$t tidak ada (fallback internal)"; fi
done
if [ -d "$APP_DIR/nuclei-templates" ]; then
  ok "template nuclei: $(find "$APP_DIR/nuclei-templates" -name '*.yaml' 2>/dev/null | wc -l) file"
else warn "template nuclei belum ada — jalankan: HOME=$APP_DIR nuclei -update-templates"; fi

step "Konfigurasi"
CFG="$APP_DIR/config.json"
if [ ! -f "$CFG" ]; then fail "config.json tidak ada"; else
  PERM=$(stat -c '%a %U' "$CFG" 2>/dev/null || echo '?')
  case "$PERM" in 600*) ok "config.json ($PERM)";; *) warn "config.json permission $PERM — sarankan 600";; esac
  if grep -q "ISI_TOKEN_DARI_BOTFATHER\|ISI_NUMERIC_CHAT_ID" "$CFG"; then
    fail "config.json masih berisi placeholder — isi bot_token & chat_id"
  fi
fi

step "Token & chat ID"
TOKEN_INFO=$("$PYTHON_BIN" - "$CFG" <<'PY' 2>&1
import json, sys, urllib.request, urllib.error
try:
    cfg = json.load(open(sys.argv[1]))
except Exception as exc:
    print("ERR|config tidak terbaca: %s" % exc); raise SystemExit
tok, chat = str(cfg.get("bot_token","")).strip(), str(cfg.get("chat_id","")).strip()
if not tok or "ISI" in tok or "TOKEN_ANDA" in tok:
    print("ERR|bot_token belum diisi"); raise SystemExit
if not chat.isdigit() and not (chat.startswith("-") and chat[1:].isdigit()):
    print("ERR|chat_id bukan numerik (%s)" % chat); raise SystemExit
try:
    with urllib.request.urlopen("https://api.telegram.org/bot%s/getMe" % tok, timeout=15) as r:
        me = json.loads(r.read())["result"]
    print("OK|@%s (%s) | chat_id=%s" % (me.get("username"), me.get("first_name"), chat))
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8","replace")[:120]
    print("ERR|getMe HTTP %s: %s" % (exc.code, body))
except Exception as exc:
    print("ERR|%s" % exc)
PY
)
if [ "${TOKEN_INFO%%|*}" = "OK" ]; then ok "${TOKEN_INFO#*|}"; else fail "${TOKEN_INFO#*|}"; fi

if [ "$SEND" -eq 1 ]; then
  step "Kirim pesan uji"
  if sudo -u "${SUDO_USER:-scanner}" "$PYTHON_BIN" "$APP_DIR/modules/monitor.py" --send >/tmp/doctor_send.log 2>&1; then
    ok "pesan terkirim — cek Telegram"
  else
    bad "gagal kirim"; tail -5 /tmp/doctor_send.log | sed 's/^/    /'
  fi
fi

step "Service bot"
if systemctl is-active --quiet scanner-bot 2>/dev/null; then
  ok "aktif sejak $(systemctl show -p ActiveEnterTimestamp --value scanner-bot 2>/dev/null)"
else
  fail "scanner-bot tidak aktif"
  systemctl status scanner-bot --no-pager 2>&1 | tail -8 | sed 's/^/    /'
fi
if command -v journalctl >/dev/null 2>&1; then
  ERRS=$(journalctl -u scanner-bot --since "1 hour ago" --no-pager 2>/dev/null | grep -ciE "error|traceback" || true)
  if [ "${ERRS:-0}" -gt 0 ]; then
    warn "$ERRS baris error/traceback dalam 1 jam terakhir:"
    journalctl -u scanner-bot --since "1 hour ago" --no-pager 2>/dev/null | grep -iE "error|traceback" | tail -4 | sed 's/^/    /'
  else ok "tidak ada error di journal 1 jam terakhir"; fi
fi

step "Jadwal & log"
TZ_NOW=$(timedatectl show -p Timezone --value 2>/dev/null || echo '?')
echo "  timezone server : $TZ_NOW"
if [ -f /etc/cron.d/scanner-bot ]; then
  grep -v '^#' /etc/cron.d/scanner-bot | grep -v '^$' | sed 's/^/  /'
  if [ "$TZ_NOW" != "Asia/Jakarta" ]; then
    warn "cron 01:00 akan jalan pada 01:00 $TZ_NOW — untuk 01:00 WIB ubah jadwal atau timezone"
  fi
else warn "file /etc/cron.d/scanner-bot tidak ada"; fi
systemctl is-active --quiet cron 2>/dev/null && ok "service cron aktif" || fail "service cron tidak aktif"
[ -f "$APP_DIR/log/cron.log" ] && echo "  cron.log terakhir: $(tail -1 "$APP_DIR/log/cron.log" 2>/dev/null | cut -c1-100)" || warn "log/cron.log belum ada (cron belum pernah jalan)"

step "Disk"
du -sh "$APP_DIR/reports" "$APP_DIR/log" 2>/dev/null | sed 's/^/  /'

step "Hasil"
if [ "$FAILS" -eq 0 ]; then
  printf '  \033[32mSemua pemeriksaan penting lolos.\033[0m\n'
else
  printf '  \033[31m%s masalah perlu diperbaiki (lihat ✗ di atas).\033[0m\n' "$FAILS"
fi
exit $([ "$FAILS" -eq 0 ] && echo 0 || echo 1)
