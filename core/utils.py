"""Utilitas bersama: logging, format angka, badge risiko."""

from __future__ import annotations

import html
import logging
import logging.handlers
import os
import socket
from datetime import datetime
from pathlib import Path

from core.settings import ROOT

LOG_DIR = Path(os.environ.get("SCAN_LOG_DIR", ROOT / "log"))
REPORT_DIR = Path(os.environ.get("SCAN_REPORT_DIR", ROOT / "reports"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

LEVEL_EMOJI = {"ok": "✅", "warn": "⚠️", "crit": "❌", "unknown": "⚪"}
RISK_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def get_logger(name: str) -> logging.Logger:
    """Logger dengan RotatingFileHandler (audit trail) + stdout."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    fh = logging.handlers.RotatingFileHandler(
        LOG_DIR / f"{name}.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    logger.propagate = False
    return logger


def h(text: object) -> str:
    """Escape untuk parse_mode=HTML Telegram."""
    return html.escape(str(text), quote=False)


def badge(level: str) -> str:
    return LEVEL_EMOJI.get(level, "⚪")


def risk_badge(risk: str) -> str:
    return RISK_EMOJI.get(risk.lower(), "⚪") + " " + risk.upper()


def now_str(label: str = "WIB") -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f" {label}"


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} TB"


def human_uptime(seconds: float) -> str:
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}h")
    if hours:
        parts.append(f"{hours}j")
    parts.append(f"{mins}m")
    return " ".join(parts)


def level_from_threshold(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "crit"
    if value >= warn:
        return "warn"
    return "ok"


def severity_from_score(score: int) -> str:
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def save_report(name: str, payload: str) -> Path:
    """Simpan salinan laporan (txt/md) untuk histori."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{name}_{stamp}.txt"
    path.write_text(payload, encoding="utf-8")
    return path
