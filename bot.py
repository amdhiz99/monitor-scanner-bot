#!/usr/bin/env python3
"""Bot Telegram — antarmuka kontrol untuk Modul A & Modul B.

Menu memakai inline keyboard + reply keyboard (bukan teks biasa):
    1️⃣ Monitoring Server   → Modul A
    2️⃣ Scan Server         → Modul B (port, konfigurasi, update)
    3️⃣ Scan Domain         → Modul B (HTTP & HTTPS untuk subdomain yang dikirim)

Bot hanya melayani ADMIN_CHAT_ID. Semua tugas berat dijalankan di thread
terpisah agar polling tetap responsif, dan setiap error ditangkap + dilaporkan.

Jalankan: python3 bot.py   (hentikan: Ctrl+C atau ./stop_bot.sh)
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.settings import ConfigError, load_config, require_telegram
from core.tg import TelegramClient, TelegramError
from core.utils import RISK_ORDER, get_logger, h, now_str

log = get_logger("bot")

STATE_FILE = Path(__file__).resolve().parent / "log" / "bot_state.json"
AWAIT_TTL = 600  # detik: permintaan domain kedaluwarsa setelah 10 menit

BTN_MONITOR = "📊 Monitoring"
BTN_SERVER = "🛡 Scan Server"
BTN_DOMAIN = "🌐 Scan Domain"
BTN_DEEP = "🔎 Deep Scan"
BTN_HELP = "❓ Bantuan"

RUNNING = True


# --------------------------------------------------------------------- helpers
def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except OSError as exc:
        log.warning("state tidak tersimpan: %s", exc)


def main_menu_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "1️⃣ Monitoring Server", "callback_data": "act:monitor"}],
            [{"text": "2️⃣ Scan Server", "callback_data": "act:server"}],
            [{"text": "3️⃣ Scan Domain", "callback_data": "act:domain"}],
            [{"text": "4️⃣ Deep Scan (CVE, OWASP & Kode)", "callback_data": "act:deep"}],
            [
                {"text": "ℹ️ Status", "callback_data": "act:status"},
            ],
        ]
    }


def reply_menu_keyboard() -> dict:
    return {
        "keyboard": [
            [{"text": BTN_MONITOR}],
            [{"text": BTN_SERVER}, {"text": BTN_DOMAIN}],
            [{"text": BTN_DEEP}],
            [{"text": BTN_HELP}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
        "input_field_placeholder": "Pilih menu atau ketik /menu",
    }


def cancel_keyboard() -> dict:
    return {"inline_keyboard": [[{"text": "✖️ Batal", "callback_data": "act:cancel"}]]}


def status_keyboard() -> dict:
    return {"inline_keyboard": [[{"text": "🏠 Menu utama", "callback_data": "act:menu"}]]}


HELP_TEXT = (
    "🤖 <b>BOT MONITORING &amp; SECURITY</b>\n\n"
    "Menu interaktif ada di bawah — cukup tekan tombolnya.\n\n"
    "1️⃣ <b>Monitoring Server</b> — uptime, CPU, RAM, disk, load, service, port\n"
    "2️⃣ <b>Scan Server</b> — port terbuka, konfigurasi rawan, update keamanan\n"
    "3️⃣ <b>Scan Domain</b> — HTTP &amp; HTTPS terpisah + SSL/TLS untuk subdomain\n"
    "4️⃣ <b>Deep Scan</b> — CVE (NVD + nuclei) &amp; OWASP Top 10\n\n"
    "<b>Perintah teks:</b>\n"
    "/menu — tampilkan menu\n"
    "/monitor — Modul A\n"
    "/scan_server — Modul B server\n"
    "/scan_domain — Modul B domain (bot minta nama domain)\n"
    "/scan contoh.com — langsung scan domain\n"
    "/deep — deep scan CVE/OWASP (lokal + domain terpantau)\n"
    "/cve contoh.com — deep scan domain tertentu\n"
    "/domains — daftar domain terpantau\n"
    "/status — status bot\n"
    "/id — chat ID Anda\n"
    "/cancel — batalkan input\n\n"
    "<i>Hanya chat admin yang dilayani.</i>"
)


class Bot:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.client = TelegramClient(
            cfg["bot_token"], cfg["chat_id"],
            timeout=int(cfg["telegram"].get("request_timeout", 20)), logger=log,
        )
        self.admin = str(cfg["chat_id"])
        self.state = load_state()
        self.offset = self.state.get("offset")
        self.awaiting: dict[str, float] = {}  # chat_id -> deadline
        self.busy: set[str] = set()
        self.lock = threading.Lock()

    # ------------------------------------------------------------- sending
    def say(self, text: str, keyboard: dict | None = None, chat_id: str | None = None):
        try:
            if chat_id and str(chat_id) != self.admin:
                target = TelegramClient(self.cfg["bot_token"], str(chat_id), logger=log)
                target.send(text, reply_markup=keyboard)
                return
            self.client.send(text, reply_markup=keyboard)
        except TelegramError as exc:
            log.error("Gagal kirim pesan: %s", exc)

    def send_menu(self, greeting: bool = False):
        intro = "🏠 <b>Menu utama</b>\nPilih salah satu:" if not greeting else (
            "👋 <b>Bot Monitoring &amp; Security siap.</b>\n"
            f"<i>{now_str(self.cfg.get('timezone_label', 'WIB'))}</i>\n\nPilih menu:"
        )
        self.say(intro, main_menu_keyboard())

    # -------------------------------------------------------------- guards
    def is_admin(self, chat_id) -> bool:
        return str(chat_id) == self.admin

    def claim(self, chat_id: str) -> bool:
        with self.lock:
            if chat_id in self.busy:
                return False
            self.busy.add(chat_id)
            return True

    def release(self, chat_id: str) -> None:
        with self.lock:
            self.busy.discard(chat_id)

    def set_awaiting(self, chat_id: str, on: bool = True) -> None:
        if on:
            self.awaiting[chat_id] = time.time() + AWAIT_TTL
        else:
            self.awaiting.pop(chat_id, None)

    def is_awaiting(self, chat_id: str) -> bool:
        deadline = self.awaiting.get(chat_id)
        if not deadline:
            return False
        if time.time() > deadline:
            self.awaiting.pop(chat_id, None)
            return False
        return True

    # -------------------------------------------------------------- actions
    def action_monitor(self, chat_id: str):
        if not self.claim(chat_id):
            self.say("⏳ Masih ada tugas berjalan. Tunggu sebentar.", status_keyboard())
            return
        try:
            self.say("⏳ Mengumpulkan metrik server...")
            from modules import monitor

            text, worst, _ = monitor.run(send=False, cfg=self.cfg)
            log.info("Monitoring via bot: status=%s", worst)
            self.say(text, status_keyboard())
        except Exception as exc:  # noqa: BLE001
            log.exception("Monitoring gagal: %s", exc)
            self.say(f"❌ <b>Monitoring gagal</b>\n<code>{exc}</code>", status_keyboard())
        finally:
            self.release(chat_id)

    def action_server(self, chat_id: str):
        if not self.claim(chat_id):
            self.say("⏳ Masih ada tugas berjalan. Tunggu sebentar.", status_keyboard())
            return
        try:
            self.say("⏳ Memindai port &amp; konfigurasi server... (bisa 1–2 menit)")
            from modules import secscan

            text, worst, _ = secscan.run_server_scan(self.cfg)
            log.info("Scan server via bot: worst=%s", worst)
            self.say(text, status_keyboard())
        except Exception as exc:  # noqa: BLE001
            log.exception("Scan server gagal: %s", exc)
            self.say(f"❌ <b>Scan server gagal</b>\n<code>{exc}</code>", status_keyboard())
        finally:
            self.release(chat_id)

    def ask_domain(self, chat_id: str):
        self.set_awaiting(chat_id, True)
        self.say(
            "🌐 <b>Scan Domain</b>\n\n"
            "Kirim nama subdomain/domain yang ingin diperiksa.\n"
            "Bisa beberapa sekaligus, pisahkan dengan koma atau baris baru.\n\n"
            "<i>Contoh:</i> <code>barlve.com</code>\n"
            "<i>Contoh banyak:</i> <code>barlve.com, www.barlve.com, api.barlve.com</code>",
            cancel_keyboard(),
        )

    def action_domains(self, chat_id: str, payload: str):
        domains = []
        for token in payload.replace("\n", ",").split(","):
            token = token.strip()
            if token and token not in domains:
                domains.append(token)
        if not domains:
            self.say("⚠️ Tidak ada domain valid. Coba lagi: /scan_domain", status_keyboard())
            return
        if len(domains) > 5:
            self.say("⚠️ Maksimal 5 domain per permintaan.", status_keyboard())
            return
        if not self.claim(chat_id):
            self.say("⏳ Masih ada tugas berjalan. Tunggu sebentar.", status_keyboard())
            return
        try:
            self.say(f"⏳ Memeriksa HTTP &amp; HTTPS untuk {len(domains)} domain...")
            from modules import secscan

            text, worst, _ = secscan.run_domain_scan(domains, self.cfg)
            log.info("Scan domain via bot: %s → %s", domains, worst)
            self.say(text, status_keyboard())
        except Exception as exc:  # noqa: BLE001
            log.exception("Scan domain gagal: %s", exc)
            self.say(f"❌ <b>Scan domain gagal</b>\n<code>{exc}</code>", status_keyboard())
        finally:
            self.release(chat_id)

    def action_deep(self, chat_id: str, domain: str | None = None):
        if not self.claim(chat_id):
            self.say("⏳ Masih ada tugas berjalan. Tunggu sebentar.", status_keyboard())
            return
        try:
            target = domain or "server lokal + domain terpantau"
            self.say(f"⏳ Deep scan CVE &amp; OWASP: {h(target)}\n"
                     "<i>Fingerprint versi → NVD → nuclei → probe aman. Bisa 1–5 menit.</i>")
            from modules import vulnscan

            if domain:
                targets = [f"https://{domain}", f"http://{domain}"]
                text, worst, _ = vulnscan.deep_scan(domain, self.cfg, local=False,
                                                    nuclei_targets=targets)
            else:
                text, worst, _ = vulnscan.run_cron_deep(self.cfg)
            log.info("Deep scan via bot: %s → %s", target, worst)
            self.say(text, status_keyboard())

            # lanjutan: deep scan kode aplikasi (whitebox)
            try:
                from modules import codescan

                kode_teks, kode_worst = codescan.run_code_scan(self.cfg)
                log.info("Deep scan kode: %s", kode_worst)
                self.say(kode_teks, status_keyboard())
            except Exception as exc:  # noqa: BLE001
                log.exception("Deep scan kode gagal: %s", exc)
                self.say(f"⚠️ <b>Deep scan kode gagal</b>\n<code>{exc}</code>", status_keyboard())
        except Exception as exc:  # noqa: BLE001
            log.exception("Deep scan gagal: %s", exc)
            self.say(f"❌ <b>Deep scan gagal</b>\n<code>{exc}</code>", status_keyboard())
        finally:
            self.release(chat_id)

    def action_status(self, chat_id: str):
        domains = self.cfg["domain_scan"].get("subdomains", [])
        busy = "ya" if chat_id in self.busy else "tidak"
        text = (
            "ℹ️ <b>Status bot</b>\n\n"
            f"Waktu: {now_str(self.cfg.get('timezone_label', 'WIB'))}\n"
            f"Admin chat: <code>{self.admin}</code>\n"
            f"Sedang memproses: <b>{busy}</b>\n"
            f"Domain terpantau: {len(domains)}\n"
            f"Menunggu input domain: {'ya' if self.is_awaiting(chat_id) else 'tidak'}\n"
            f"Config: <code>{self.cfg.get('_path')}</code>\n"
            f"Jadwal cron: 01:00 {self.cfg.get('timezone_label', 'WIB')} (Modul A → Modul B)"
        )
        self.say(text, status_keyboard())

    def action_list_domains(self, chat_id: str):
        domains = self.cfg["domain_scan"].get("subdomains", [])
        if not domains:
            self.say(
                "📋 Belum ada domain terpantau.\n"
                "Tambahkan di <code>config.json</code> → <code>domain_scan.subdomains</code>,\n"
                "atau pakai tombol 3️⃣ untuk scan langsung.",
                status_keyboard(),
            )
            return
        lines = ["📋 <b>Domain terpantau</b>", ""]
        for dom in domains:
            lines.append(f"• <code>{dom}</code>")
        lines.append("")
        lines.append("<i>Scan otomatis ikut dijalankan pada cron 01:00.</i>")
        self.say("\n".join(lines), status_keyboard())

    # ------------------------------------------------------------ dispatch
    def handle_callback(self, cq: dict):
        chat_id = str(cq.get("message", {}).get("chat", {}).get("id", ""))
        data = cq.get("data", "")
        self.client.answer_callback(cq.get("id", ""))
        if not self.is_admin(chat_id):
            self.say("⛔ Anda tidak berhak memakai bot ini. Kirim /id untuk melihat chat ID Anda.",
                     chat_id=chat_id)
            return
        action = data.split(":", 1)[1] if ":" in data else data
        log.info("Callback dari %s: %s", chat_id, action)
        if action == "monitor":
            threading.Thread(target=self.action_monitor, args=(chat_id,), daemon=True).start()
        elif action == "server":
            threading.Thread(target=self.action_server, args=(chat_id,), daemon=True).start()
        elif action == "domain":
            self.ask_domain(chat_id)
        elif action == "deep":
            threading.Thread(target=self.action_deep, args=(chat_id,), daemon=True).start()
        elif action == "list_domains":
            self.action_list_domains(chat_id)
        elif action == "status":
            self.action_status(chat_id)
        elif action == "cancel":
            self.set_awaiting(chat_id, False)
            self.say("✖️ Dibatalkan. Kembali ke menu.", main_menu_keyboard())
        elif action == "menu":
            self.send_menu()
        else:
            self.say("Menu tidak dikenal. Ketik /menu.", main_menu_keyboard())

    def handle_message(self, msg: dict):
        chat_id = str(msg.get("chat", {}).get("id", ""))
        text = (msg.get("text") or "").strip()
        if not text:
            return
        log.info("Pesan dari %s: %s", chat_id, text[:80])

        if not self.is_admin(chat_id):
            self.say(f"⛔ Bot ini privat.\nChat ID Anda: <code>{chat_id}</code>", chat_id=chat_id)
            return

        lower = text.lower()
        if lower.startswith("/id"):
            self.say(f"🆔 Chat ID Anda: <code>{chat_id}</code>")
            return
        if lower.startswith("/start"):
            self.say(HELP_TEXT, reply_menu_keyboard())
            self.send_menu(greeting=True)
            return
        if lower.startswith("/help"):
            self.say(HELP_TEXT, main_menu_keyboard())
            return
        if lower.startswith("/menu"):
            self.send_menu()
            return
        if lower.startswith("/status"):
            self.action_status(chat_id)
            return
        if lower.startswith("/domains"):
            self.action_list_domains(chat_id)
            return
        if lower.startswith("/cancel"):
            self.set_awaiting(chat_id, False)
            self.say("✖️ Dibatalkan.", main_menu_keyboard())
            return
        if lower.startswith("/deep"):
            threading.Thread(target=self.action_deep, args=(chat_id,), daemon=True).start()
            return
        if lower.startswith("/cve"):
            parts = text.split(maxsplit=1)
            domain = parts[1].strip() if len(parts) > 1 else ""
            threading.Thread(target=self.action_deep, args=(chat_id, domain or None),
                             daemon=True).start()
            return
        if lower.startswith("/monitor"):
            threading.Thread(target=self.action_monitor, args=(chat_id,), daemon=True).start()
            return
        if lower.startswith("/scan_server") or lower.startswith("/server"):
            threading.Thread(target=self.action_server, args=(chat_id,), daemon=True).start()
            return
        if lower.startswith("/scan_domain") or lower.startswith("/domain"):
            arg = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
            if arg:
                threading.Thread(target=self.action_domains, args=(chat_id, arg), daemon=True).start()
            else:
                self.ask_domain(chat_id)
            return
        if lower.startswith("/scan "):
            arg = text.split(maxsplit=1)[1]
            threading.Thread(target=self.action_domains, args=(chat_id, arg), daemon=True).start()
            return

        # tombol reply keyboard
        if text == BTN_MONITOR:
            threading.Thread(target=self.action_monitor, args=(chat_id,), daemon=True).start()
            return
        if text == BTN_SERVER:
            threading.Thread(target=self.action_server, args=(chat_id,), daemon=True).start()
            return
        if text == BTN_DOMAIN:
            self.ask_domain(chat_id)
            return
        if text == BTN_DEEP:
            threading.Thread(target=self.action_deep, args=(chat_id,), daemon=True).start()
            return
        if text == BTN_HELP:
            self.say(HELP_TEXT, main_menu_keyboard())
            return

        # sedang menunggu nama domain
        if self.is_awaiting(chat_id):
            self.set_awaiting(chat_id, False)
            threading.Thread(target=self.action_domains, args=(chat_id, text), daemon=True).start()
            return

        self.say("Ketik /menu untuk membuka menu.", main_menu_keyboard())

    # --------------------------------------------------------------- loop
    def poll_once(self) -> None:
        updates = self.client.get_updates(self.offset, timeout=30)
        for upd in updates or []:
            self.offset = upd.get("update_id", 0) + 1
            try:
                if "message" in upd:
                    self.handle_message(upd["message"])
                elif "callback_query" in upd:
                    self.handle_callback(upd["callback_query"])
            except Exception as exc:  # noqa: BLE001 - satu update gagal jangan matikan bot
                log.exception("Error memproses update: %s", exc)
                self.say(f"❌ Terjadi kesalahan internal:\n<code>{exc}</code>", status_keyboard())
            save_state({"offset": self.offset})

    def run(self) -> None:
        log.info("Bot mulai (admin=%s, config=%s)", self.admin, self.cfg.get("_path"))
        # Hindari memutar ulang perintah lama setelah restart: tandai update terakhir
        # sebagai sudah dibaca bila belum ada offset tersimpan.
        if self.offset is None:
            try:
                pending = self.client.get_updates(-1, timeout=0) or []
                if pending:
                    self.offset = pending[-1].get("update_id", 0) + 1
                    save_state({"offset": self.offset})
                    log.info("Offset awal diset ke %s (backlog dilewati)", self.offset)
            except TelegramError as exc:
                log.warning("Gagal inisialisasi offset: %s", exc)
        self.say(
            f"🚀 <b>Bot aktif</b>\n<i>{now_str(self.cfg.get('timezone_label', 'WIB'))}</i>\n\n"
            "Laporan otomatis dikirim setiap 01:00 (Modul A → Modul B).",
            reply_menu_keyboard(),
        )
        self.send_menu(greeting=True)
        failures = 0
        while RUNNING:
            try:
                self.poll_once()
                failures = 0
            except TelegramError as exc:
                failures += 1
                msg = str(exc)
                if "409" in msg or "terminated by other" in msg:
                    log.error("Konflik polling: instance bot lain masih jalan. "
                              "Hentikan dulu (./stop_bot.sh).")
                    time.sleep(5)
                else:
                    backoff = min(5 * failures, 60)
                    log.warning("Polling gagal (%s) — retry %ss", msg[:160], backoff)
                    time.sleep(backoff)
            except KeyboardInterrupt:
                break
            except Exception as exc:  # noqa: BLE001
                failures += 1
                log.error("Loop error: %s\n%s", exc, traceback.format_exc())
                time.sleep(min(5 * failures, 60))
        log.info("Bot berhenti")


def _signal(signum, _frame):
    global RUNNING
    RUNNING = False
    log.info("Menerima signal %s, menghentikan bot...", signum)


def main() -> int:
    try:
        cfg = load_config()
        require_telegram(cfg)
    except ConfigError as exc:
        print(f"ERROR konfigurasi: {exc}", file=sys.stderr)
        return 1
    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)
    try:
        Bot(cfg).run()
    except Exception as exc:  # noqa: BLE001
        log.exception("Bot berhenti karena error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
