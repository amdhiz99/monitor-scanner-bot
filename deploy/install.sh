#!/usr/bin/env bash
# Instalasi scanner di server (Ubuntu/Debian). Idempoten — aman dijalankan ulang.
#
#   sudo ./deploy/install.sh              # pasang semua (deps, user, service, cron)
#   sudo ./deploy/install.sh --no-nuclei  # tanpa nuclei (Modul C tetap jalan)
#   ./deploy/install.sh --check           # hanya cek prasyarat, tidak mengubah apa pun
#
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/scanner-bot}"
APP_USER="${APP_USER:-scanner}"
REPO_URL="${REPO_URL:-https://github.com/amdhiz99/monitor-scanner-bot.git}"
TARGET_TZ="${TARGET_TZ:-Asia/Jakarta}"
INSTALL_NUCLEI=1
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --no-nuclei) INSTALL_NUCLEI=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "argumen tidak dikenal: $arg"; exit 2 ;;
  esac
done

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------- prasyarat
step "Memeriksa prasyarat"

# utamakan python sistem (venv Hermes/tooling lain bisa mengacaukan cron)
if [ -n "${PYTHON_BIN:-}" ] && [ -x "${PYTHON_BIN}" ]; then :
elif [ -x /usr/bin/python3 ]; then PYTHON_BIN=/usr/bin/python3
else PYTHON_BIN="$(command -v python3 || true)"
fi
if [ -z "$PYTHON_BIN" ]; then
  bad "python3 tidak ada"; exit 1
fi
PY_VER="$("$PYTHON_BIN" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
if "$PYTHON_BIN" - <<'PY'
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
then ok "python3 $PY_VER ($PYTHON_BIN)"; else bad "python3 $PY_VER < 3.8"; exit 1; fi

for tool in git curl; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool tersedia"; else warn "$tool belum ada (akan dipasang)"; fi
done
for tool in nmap openssl ss; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool tersedia"; else warn "$tool belum ada (fallback internal dipakai)"; fi
done
if command -v nuclei >/dev/null 2>&1; then
  NUC_VER="$(nuclei -version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  ok "nuclei ${NUC_VER:-terpasang}"
else
  warn "nuclei belum ada — Modul C jalan tanpa template CVE"
fi

TZ_NOW="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo unknown)"
if [ "$TZ_NOW" = "$TARGET_TZ" ]; then ok "timezone $TZ_NOW"; else warn "timezone $TZ_NOW (jadwal cron mengasumsikan $TARGET_TZ)"; fi

if [ "$(id -u)" -eq 0 ]; then ok "dijalankan sebagai root"; else warn "bukan root — mode --check saja yang bisa"; fi

# Modul tidak boleh butuh paket pip
if "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import urllib.request, ssl, socket, http.client, json
PY
then ok "modul standard library lengkap"; else bad "standard library tidak lengkap"; fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  step "Mode --check selesai (tidak ada perubahan)"
  echo "  Jalankan 'sudo $0' untuk instalasi sebenarnya."
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { bad "instalasi butuh root (sudo)"; exit 1; }

# ------------------------------------------------------------------- paket
step "Memasang paket sistem"
export DEBIAN_FRONTEND=noninteractive
PKGS="python3 git curl unzip ca-certificates nmap openssl iproute2 update-notifier-common"
if apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq $PKGS >/dev/null 2>&1; then
  ok "paket terpasang: $PKGS"
else
  warn "sebagian paket gagal dipasang — scanner tetap jalan dengan fallback internal"
fi

step "Menyetel timezone"
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-timezone "$TARGET_TZ" 2>/dev/null && ok "timezone = $TARGET_TZ" || warn "timezone tidak berubah"
else
  warn "timedatectl tidak tersedia"
fi

# -------------------------------------------------------------- user & kode
step "Menyiapkan user dan kode"
if id "$APP_USER" >/dev/null 2>&1; then
  ok "user $APP_USER sudah ada"
else
  useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
  ok "user $APP_USER dibuat"
fi

mkdir -p "$APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only && ok "kode diperbarui (git pull)"
elif [ -f "$APP_DIR/bot.py" ]; then
  ok "kode sudah ada di $APP_DIR (bukan clone git)"
else
  if git clone -q "$REPO_URL" "$APP_DIR" 2>/dev/null; then
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    ok "kode di-clone dari $REPO_URL"
  else
    cp -a "$PROJECT_DIR/." "$APP_DIR/"
    ok "kode disalin dari $PROJECT_DIR (clone gagal / offline)"
  fi
fi
chown -R "$APP_USER:$APP_USER" "$APP_DIR" 2>/dev/null || true
find "$APP_DIR" -maxdepth 1 -name '*.sh' -exec chmod +x {} \;
mkdir -p "$APP_DIR/log" "$APP_DIR/reports"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/log" "$APP_DIR/reports"

# --------------------------------------------------------------- konfigurasi
step "Konfigurasi"
if [ -f "$APP_DIR/config.json" ]; then
  ok "config.json sudah ada (tidak ditimpa)"
else
  cp "$APP_DIR/config.example.json" "$APP_DIR/config.json"
  chown "$APP_USER:$APP_USER" "$APP_DIR/config.json"
  chmod 600 "$APP_DIR/config.json"
  warn "config.json dibuat dari contoh — ISI bot_token, chat_id, dan subdomains!"
fi
chmod 600 "$APP_DIR/config.json" 2>/dev/null || true
if [ -f "$APP_DIR/.env" ]; then chmod 600 "$APP_DIR/.env"; fi

# ------------------------------------------------------------------- nuclei
if [ "$INSTALL_NUCLEI" -eq 1 ] && ! command -v nuclei >/dev/null 2>&1; then
  step "Memasang nuclei"
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) GOARCH=amd64 ;; aarch64|arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
  VER="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -oP '"tag_name":\s*"v\K[^"]+' | head -1 || true)"
  if [ -n "${VER:-}" ] && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${VER}/nuclei_${VER}_linux_${GOARCH}.zip"; then
    unzip -o -q /tmp/nuclei.zip -d /usr/local/bin nuclei && chmod +x /usr/local/bin/nuclei
    rm -f /tmp/nuclei.zip
    ok "nuclei v$VER terpasang di /usr/local/bin"
    HOME="$APP_DIR" nuclei -update-templates >/dev/null 2>&1 && ok "template di $APP_DIR/nuclei-templates" || warn "template belum terunduh"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR" 2>/dev/null || true
  else
    warn "nuclei tidak terpasang (unduh manual dari GitHub releases)"
  fi
fi

# ------------------------------------------------------------ service & cron
step "Memasang systemd unit dan cron"
install -m 644 "$APP_DIR/deploy/scanner-bot.service" /etc/systemd/system/scanner-bot.service
ok "/etc/systemd/system/scanner-bot.service"
systemctl daemon-reload
systemctl enable scanner-bot >/dev/null 2>&1 && ok "service di-enable saat boot"

install -m 644 "$APP_DIR/deploy/scanner-bot.cron" /etc/cron.d/scanner-bot
ok "/etc/cron.d/scanner-bot (01:00 waktu server)"

# ----------------------------------------------------------------- uji cepat
step "Uji cepat modul (tanpa kirim ke Telegram)"
cd "$APP_DIR"
if sudo -u "$APP_USER" "$PYTHON_BIN" -m modules.monitor >/dev/null 2>&1; then ok "Modul A jalan"; else bad "Modul A gagal"; fi
if sudo -u "$APP_USER" "$PYTHON_BIN" -m modules.secscan server --target 127.0.0.1 >/dev/null 2>&1; then ok "Modul B server jalan"; else warn "Modul B server bermasalah"; fi
if sudo -u "$APP_USER" "$PYTHON_BIN" -m modules.vulnscan --local --no-nuclei >/dev/null 2>&1; then ok "Modul C jalan"; else warn "Modul C bermasalah"; fi

systemctl restart scanner-bot
sleep 3
if systemctl is-active --quiet scanner-bot; then
  ok "bot aktif (systemd)"
else
  bad "bot tidak aktif — cek: journalctl -u scanner-bot -n 40 --no-pager"
fi

step "Selesai"
cat <<EOF

  Langkah wajib berikutnya:
    1. sudo nano $APP_DIR/config.json      # isi bot_token, chat_id, subdomains
    2. sudo systemctl restart scanner-bot
    3. sudo -u $APP_USER $PYTHON_BIN $APP_DIR/modules/monitor.py --send   # uji kirim
    4. Kirim /start ke bot di Telegram

  Log    : journalctl -u scanner-bot -f   |   tail -f $APP_DIR/log/cron.log
  Jadwal : 01:00 $TARGET_TZ (Modul A → B → C)

EOF
