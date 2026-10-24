"""Pemuatan konfigurasi terpusat (config.json + override environment)."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("SCAN_CONFIG", ROOT / "config.json"))

DEFAULTS: dict[str, Any] = {
    "bot_token": "",
    "chat_id": "",
    "timezone_label": "WIB",
    "monitor": {
        "cpu": {"warn": 80, "crit": 95},
        "ram": {"warn": 80, "crit": 95},
        "disk": {"warn": 80, "crit": 90},
        "load_per_core": {"warn": 1.0, "crit": 2.0},
        "temperature": {"warn": 70, "crit": 85},
        "services": ["nginx", "apache2", "mysql", "mariadb", "postgresql", "ssh", "docker"],
        "services_critical": ["ssh"],
        "watch_ports": [22, 80, 443],
        "exclude_mounts": ["/snap", "/boot/efi", "/dev", "/run", "/sys", "/proc"],
        "top_processes": 0,
    },
    "server_scan": {
        "nmap_enabled": True,
        "nmap_profile": "top200",
        "nmap_extra_ports": "",
        "socket_fallback_ports": [22, 80, 443, 3306, 5432, 8080],
        "timeout": 300,
        "check_updates": True,
        "check_ssh_config": True,
        "risky_ports": {},
    },
    "domain_scan": {
        "subdomains": [],
        "timeout": 10,
        "max_redirects": 5,
        "cert_warn_days": 14,
        "cert_crit_days": 7,
        "check_security_headers": True,
        "weak_ciphers": ["3DES", "RC4", "NULL", "EXPORT", "MD5"],
    },
    "telegram": {"chunk_size": 3800, "request_timeout": 20},
    "deep_scan": {
        "enabled": True,
        "nvd": {"enabled": True, "api_key": "", "max_products": 8,
                "recent_months": 12, "recent_windows": 2,
                "recent_products": ["php", "nodejs", "nginx"],
                "cache_hours": 24, "timeout": 25},
        "nuclei": {"enabled": True, "path": "nuclei", "severity": "critical,high,medium",
                   "tags": "cve,owasp,exposures,misconfig", "rate_limit": 80,
                   "request_timeout": 8, "timeout": 420, "max_hosts": 3},
        "safe_exploit": True,
        "cron_deep": True,
        "cve_watch": [],
    },
}


class ConfigError(RuntimeError):
    pass


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None) -> dict:
    """Baca config.json, merge dengan default, lalu override dari environment."""
    cfg_path = Path(path or CONFIG_PATH)
    data: dict = {}
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config.json tidak valid: {exc}") from exc
    cfg = _merge(DEFAULTS, data)

    # Environment menang atas file: memudahkan cron/CI tanpa menyimpan token di repo.
    cfg["bot_token"] = os.environ.get("BOT_TOKEN") or cfg.get("bot_token", "")
    cfg["chat_id"] = os.environ.get("ADMIN_CHAT_ID") or cfg.get("chat_id", "")
    cfg["chat_id"] = str(cfg["chat_id"]).strip()
    cfg["bot_token"] = str(cfg["bot_token"]).strip()
    cfg["_path"] = str(cfg_path)
    return cfg


def require_telegram(cfg: dict) -> None:
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        raise ConfigError(
            "bot_token / chat_id belum diisi. Isi config.json atau set BOT_TOKEN & ADMIN_CHAT_ID."
        )
    if not cfg["chat_id"].lstrip("-").isdigit():
        raise ConfigError("chat_id harus numerik (bukan @username) untuk chat pribadi.")
