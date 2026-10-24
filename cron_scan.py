#!/usr/bin/env python3
"""Runner cron: Modul A (monitoring) lalu Modul B (security scan) berurutan.

Dipanggil oleh crontab / run_cron.sh:
    python3 cron_scan.py                 # monitoring + scan server + domain terjadwal
    python3 cron_scan.py --skip-domains  # hanya monitoring + scan server
    python3 cron_scan.py --no-send       # cetak ke stdout saja (testing)

Setiap tahap dibungkus try/except: satu kegagalan tidak menghentikan tahap lain,
dan kegagalan dilaporkan ke Telegram supaya tidak silent.
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.settings import load_config, require_telegram
from core.tg import TelegramClient, TelegramError
from core.utils import get_logger, now_str

log = get_logger("cron")


def send(cfg: dict, text: str) -> bool:
    try:
        require_telegram(cfg)
        TelegramClient(cfg["bot_token"], cfg["chat_id"], logger=log).send(text)
        return True
    except (TelegramError, RuntimeError) as exc:
        log.error("Gagal kirim ke Telegram: %s", exc)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Cron: monitoring + security scan")
    parser.add_argument("--no-send", action="store_true", help="jangan kirim ke Telegram")
    parser.add_argument("--skip-domains", action="store_true", help="lewati scan domain terjadwal")
    parser.add_argument("--skip-monitor", action="store_true")
    parser.add_argument("--skip-deep", action="store_true",
                        help="lewati Modul C (CVE/OWASP) yang lebih berat")
    args = parser.parse_args()

    cfg = load_config()
    started = time.time()
    log.info("=== Cron run dimulai (%s) ===", now_str(cfg.get("timezone_label", "WIB")))
    failures: list[str] = []
    worst_overall = "ok"

    # ---------- Modul A
    if not args.skip_monitor:
        try:
            from modules import monitor

            text, worst, _ = monitor.run(send=False, cfg=cfg)
            if worst == "crit":
                worst_overall = "crit"
            elif worst == "warn" and worst_overall == "ok":
                worst_overall = "warn"
            if args.no_send:
                print(text, flush=True)
            elif not send(cfg, text):
                failures.append("monitoring")
        except Exception as exc:  # noqa: BLE001
            log.exception("Modul A gagal: %s", exc)
            failures.append("monitoring")
            if not args.no_send:
                send(cfg, f"❌ <b>Monitoring gagal</b>\n<code>{exc}</code>\n"
                          f"<i>{now_str(cfg.get('timezone_label', 'WIB'))}</i>")

    # ---------- Modul B: server
    try:
        from modules import secscan

        text, worst, _ = secscan.run_server_scan(cfg)
        if args.no_send:
            print(text, flush=True)
        elif not send(cfg, text):
            failures.append("scan server")
    except Exception as exc:  # noqa: BLE001
        log.exception("Modul B (server) gagal: %s", exc)
        failures.append("scan server")
        if not args.no_send:
            send(cfg, f"❌ <b>Security scan server gagal</b>\n<code>{exc}</code>")

    # ---------- Modul B: domain terjadwal (daftar di config.json)
    domains = cfg["domain_scan"].get("subdomains", [])
    if domains and not args.skip_domains:
        try:
            from modules import secscan

            text, worst, _ = secscan.run_domain_scan(domains, cfg)
            if args.no_send:
                print(text, flush=True)
            elif not send(cfg, text):
                failures.append("scan domain")
        except Exception as exc:  # noqa: BLE001
            log.exception("Modul B (domain) gagal: %s", exc)
            failures.append("scan domain")
            if not args.no_send:
                send(cfg, f"❌ <b>Security scan domain gagal</b>\n<code>{exc}</code>")

    # ---------- Modul C: CVE + OWASP deep scan (stack lokal & domain)
    if cfg.get("deep_scan", {}).get("enabled") and cfg.get("deep_scan", {}).get("cron_deep") \
            and not args.skip_deep:
        try:
            from modules import vulnscan

            text, worst, _ = vulnscan.run_cron_deep(cfg)
            if args.no_send:
                print(text, flush=True)
            elif not send(cfg, text):
                failures.append("deep scan")
        except Exception as exc:  # noqa: BLE001
            log.exception("Modul C gagal: %s", exc)
            failures.append("deep scan")
            if not args.no_send:
                send(cfg, f"❌ <b>Deep scan (CVE/OWASP) gagal</b>\n<code>{exc}</code>")

    duration = round(time.time() - started, 1)
    if failures:
        log.error("Cron run selesai dengan kegagalan: %s (%.1fs)", ", ".join(failures), duration)
        return 1
    log.info("=== Cron run selesai OK (%s, %.1fs) ===", worst_overall, duration)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log.warning("Dihentikan oleh pengguna")
        raise SystemExit(130)
    except Exception:  # noqa: BLE001 - jangan biarkan traceback mentah di cron mail
        log.error("Fatal: %s", traceback.format_exc())
        raise SystemExit(1)
