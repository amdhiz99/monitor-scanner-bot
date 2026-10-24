#!/usr/bin/env python3
"""MODUL A — Monitoring Server.

Mengumpulkan uptime, CPU, RAM, disk per partisi, load average, status service,
koneksi aktif / port penting, dan suhu (bila tersedia) lalu memformatnya untuk
Telegram. Semua pembacaan memakai /proc & utilitas sistem — tanpa dependensi pip.

Pemakaian:
    python3 -m modules.monitor              # cetak ke stdout
    python3 -m modules.monitor --send       # kirim ke Telegram
    python3 -m modules.monitor --json       # keluaran JSON mentah
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # dukung `python3 modules/monitor.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.settings import load_config
from core.tg import TelegramClient
from core.utils import (
    badge,
    get_logger,
    h,
    hostname,
    human_bytes,
    human_uptime,
    level_from_threshold,
    now_str,
    save_report,
)

log = get_logger("monitor")


# --------------------------------------------------------------------- helpers
def sh(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    """Jalankan perintah, kembalikan (returncode, stdout+stderr). Tidak pernah raise."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, str(exc)


def read_cpu_times() -> tuple[int, int]:
    with open("/proc/stat", encoding="utf-8") as fh:
        fields = fh.readline().split()[1:]
    values = [int(v) for v in fields]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return total, idle


def cpu_percent(interval: float = 0.5) -> float:
    try:
        t1, i1 = read_cpu_times()
        time.sleep(interval)
        t2, i2 = read_cpu_times()
        dt, di = t2 - t1, i2 - i1
        if dt <= 0:
            return 0.0
        return round(max(0.0, min(100.0, (1.0 - di / dt) * 100.0)), 1)
    except (OSError, ValueError, IndexError) as exc:
        log.warning("gagal baca /proc/stat: %s", exc)
        return 0.0


def memory_info() -> dict:
    info = {"total": 0, "available": 0, "used": 0, "percent": 0.0,
            "swap_total": 0, "swap_used": 0, "swap_percent": 0.0}
    try:
        raw = {}
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                raw[key.strip()] = int(rest.split()[0]) * 1024
        total = raw.get("MemTotal", 0)
        available = raw.get("MemAvailable", raw.get("MemFree", 0))
        used = max(0, total - available)
        info.update(
            total=total,
            available=available,
            used=used,
            percent=round(used / total * 100, 1) if total else 0.0,
        )
        st = raw.get("SwapTotal", 0)
        sf = raw.get("SwapFree", 0)
        sused = max(0, st - sf)
        info.update(
            swap_total=st, swap_used=sused,
            swap_percent=round(sused / st * 100, 1) if st else 0.0,
        )
    except (OSError, ValueError) as exc:
        log.warning("gagal baca /proc/meminfo: %s", exc)
    return info


def disk_info(exclude: list[str]) -> list[dict]:
    """Partisi nyata (dari /proc/mounts, hanya device /dev/*), unik per device."""
    seen: set[str] = set()
    out: list[dict] = []
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        log.warning("gagal baca /proc/mounts: %s", exc)
        return out

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mount, fstype = parts[0], parts[1], parts[2]
        if not device.startswith("/dev/"):
            continue
        if fstype in {"squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs"}:
            continue
        if any(mount == ex or mount.startswith(ex.rstrip("/") + "/") for ex in exclude):
            continue
        if device in seen:
            continue
        seen.add(device)
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        out.append(
            {
                "mount": mount,
                "device": device,
                "fstype": fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": round(usage.used / usage.total * 100, 1) if usage.total else 0.0,
            }
        )
    out.sort(key=lambda d: d["mount"])
    return out


def load_average() -> tuple[float, float, float]:
    try:
        return os.getloadavg()
    except OSError:
        return (0.0, 0.0, 0.0)


def uptime_seconds() -> float:
    try:
        with open("/proc/uptime", encoding="utf-8") as fh:
            return float(fh.readline().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def systemd_available() -> bool:
    code, out = sh(["systemctl", "is-system-running"], timeout=5)
    text = out.lower()
    return code == 0 or any(w in text for w in ("running", "degraded", "starting", "maintenance"))


SYSTEMD_OK = systemd_available()


def service_status(name: str) -> dict:
    """Status service: active | inactive | failed | not-installed | unknown.

    `systemctl is-active` mengembalikan "inactive" untuk unit yang tidak ada,
    jadi keberadaan unit dicek lewat LoadState lebih dulu.
    """
    aliases = {"sshd": "ssh", "mysql": "mysqld", "apache": "apache2"}
    unit = aliases.get(name, name)
    if SYSTEMD_OK:
        code, out = sh(["systemctl", "show", "-p", "LoadState", "-p", "ActiveState",
                        "--value", f"{unit}.service"], timeout=5)
        states = [s.strip() for s in out.strip().splitlines() if s.strip()]
        load_state = states[0] if states else ""
        active_state = states[1] if len(states) > 1 else ""
        if load_state == "loaded":
            if active_state in {"active", "reloading", "activating"}:
                return {"name": name, "state": "active", "via": "systemd"}
            if active_state in {"inactive", "failed", "deactivating"}:
                return {"name": name, "state": active_state, "via": "systemd"}
    for pattern in (["pgrep", "-x", name], ["pgrep", "-f", f"/usr/sbin/{name}"]):
        code, out = sh(pattern, timeout=5)
        if code == 0 and out.strip():
            return {"name": name, "state": "active", "via": "process"}
    return {"name": name, "state": "not-installed", "via": "none"}


def listening_ports() -> list[int]:
    ports: set[int] = set()
    code, out = sh(["ss", "-H", "-ltn"], timeout=10)
    if code == 0:
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            local = cols[3]
            if ":" in local:
                try:
                    ports.add(int(local.rsplit(":", 1)[1]))
                except ValueError:
                    pass
        if ports:
            return sorted(ports)
    # fallback /proc/net/tcp{,6}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="utf-8") as fh:
                next(fh)
                for line in fh:
                    fields = line.split()
                    if len(fields) > 3 and fields[3] == "0A":  # LISTEN
                        ports.add(int(fields[1].rsplit(":", 1)[1], 16))
        except (OSError, ValueError, StopIteration):
            continue
    return sorted(ports)


def established_connections() -> int:
    code, out = sh(["ss", "-H", "-tun", "state", "established"], timeout=10)
    if code == 0:
        return sum(1 for line in out.splitlines() if line.strip())
    count = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="utf-8") as fh:
                next(fh)
                count += sum(1 for line in fh if len(line.split()) > 3 and line.split()[3] == "01")
        except (OSError, StopIteration):
            continue
    return count


def temperature() -> float | None:
    temps: list[float] = []
    for zone in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            val = float(Path(zone).read_text(encoding="utf-8").strip()) / 1000.0
            if -20 <= val <= 150:
                temps.append(val)
        except (OSError, ValueError):
            continue
    if temps:
        return round(max(temps), 1)
    code, out = sh(["sensors", "-u"], timeout=8)
    if code == 0:
        found = [float(m) for m in re.findall(r"_input:\s*([\d.]+)", out) if 0 < float(m) < 150]
        if found:
            return round(max(found), 1)
    return None


def top_processes(limit: int = 3) -> list[dict]:
    if limit <= 0:
        return []
    code, out = sh(["ps", "-eo", "comm,%cpu,%mem", "--sort=-%cpu", "--no-headers"], timeout=10)
    rows: list[dict] = []
    if code == 0:
        for line in out.splitlines()[:limit]:
            parts = line.split()
            if len(parts) >= 3:
                rows.append({"name": parts[0], "cpu": parts[1], "mem": parts[2]})
    return rows


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"


# -------------------------------------------------------------------- collect
def collect(cfg: dict | None = None) -> dict:
    cfg = cfg or load_config()
    mcfg = cfg["monitor"]
    cpu = cpu_percent()
    ram = memory_info()
    disks = disk_info(mcfg.get("exclude_mounts", []))
    load1, load5, load15 = load_average()
    cores = os.cpu_count() or 1
    listen = listening_ports()
    services = [service_status(name) for name in mcfg.get("services", [])]
    temp = temperature()
    data = {
        "host": hostname(),
        "ip": primary_ip(),
        "time": now_str(cfg.get("timezone_label", "WIB")),
        "uptime_seconds": uptime_seconds(),
        "cpu": cpu,
        "cores": cores,
        "ram": ram,
        "disks": disks,
        "load": {"1": load1, "5": load5, "15": load15, "cores": cores},
        "services": services,
        "listening_ports": listen,
        "watch_ports": [p for p in mcfg.get("watch_ports", []) if p in listen],
        "watch_ports_missing": [p for p in mcfg.get("watch_ports", []) if p not in listen],
        "connections": established_connections(),
        "temperature": temp,
        "top_processes": top_processes(int(mcfg.get("top_processes", 0))),
        "systemd": SYSTEMD_OK,
    }
    return data


# --------------------------------------------------------------------- format
def format_report(data: dict, cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    mcfg = cfg["monitor"]
    th = {
        "cpu": mcfg["cpu"],
        "ram": mcfg["ram"],
        "disk": mcfg["disk"],
        "temp": mcfg["temperature"],
    }
    worst = "ok"

    def mark(level: str) -> str:
        nonlocal worst
        order = {"ok": 0, "warn": 1, "crit": 2}
        if order.get(level, 0) > order.get(worst, 0):
            worst = level
        return badge(level)

    ram = data["ram"]
    load = data["load"]
    cores = max(1, int(load.get("cores", 1)))
    load_ratio = float(load["1"]) / cores
    load_level = level_from_threshold(load_ratio, mcfg["load_per_core"]["warn"], mcfg["load_per_core"]["crit"])

    lines: list[str] = [
        "🖥️ <b>MONITORING SERVER</b>",
        f"<i>{h(data['time'])}</i>",
        f"Host: <code>{h(data['host'])}</code> · IP: <code>{h(data['ip'])}</code>",
        "",
        f"⏱ Uptime: <b>{human_uptime(data['uptime_seconds'])}</b>",
        f"🔥 CPU: <b>{data['cpu']}%</b> {mark(level_from_threshold(data['cpu'], th['cpu']['warn'], th['cpu']['crit']))} "
        f"<i>({cores} core)</i>",
        f"🧠 RAM: <b>{human_bytes(ram['used'])} / {human_bytes(ram['total'])}</b> "
        f"({ram['percent']}%) {mark(level_from_threshold(ram['percent'], th['ram']['warn'], th['ram']['crit']))}",
    ]
    if ram["swap_total"]:
        lines.append(
            f"♻️ Swap: {human_bytes(ram['swap_used'])} / {human_bytes(ram['swap_total'])} "
            f"({ram['swap_percent']}%)"
        )

    if data["disks"]:
        lines.append("")
        lines.append("💾 <b>Disk</b>")
        for disk in data["disks"]:
            lvl = level_from_threshold(disk["percent"], th["disk"]["warn"], th["disk"]["crit"])
            lines.append(
                f"  {mark(lvl)} <code>{h(disk['mount'])}</code>: "
                f"{human_bytes(disk['used'])} / {human_bytes(disk['total'])} ({disk['percent']}%)"
            )
    else:
        lines.append("💾 Disk: ⚪ tidak ada partisi terbaca")

    lines.append(
        f"⚙️ Load: <b>{load['1']:.2f} / {load['5']:.2f} / {load['15']:.2f}</b> "
        f"{mark(load_level)} <i>(rasio {load_ratio:.2f}/core)</i>"
    )

    lines.append("")
    lines.append("🔧 <b>Service</b>")
    label = {"inactive": "mati", "failed": "gagal", "deactivating": "berhenti"}
    critical = set(mcfg.get("services_critical", ["ssh"]))
    seen_any = False
    for svc in data["services"]:
        state = svc["state"]
        if state in {"not-installed", "unknown"}:
            continue  # tidak terpasang bukan temuan
        seen_any = True
        if state == "active":
            lines.append(f"  ✅ {h(svc['name'])}: aktif")
        else:
            lvl = "crit" if svc["name"] in critical else "warn"
            lines.append(f"  {mark(lvl)} {h(svc['name'])}: {label.get(state, state)}")
    if not seen_any:
        lines.append("  ⚪ tidak ada service terpantau yang terpasang")
    skipped = [s["name"] for s in data["services"] if s["state"] == "not-installed"]
    if skipped:
        lines.append(f"  <i>(tidak terpasang: {h(', '.join(skipped))})</i>")

    ports = data["listening_ports"]
    shown = ", ".join(str(p) for p in ports[:25]) or "-"
    more = f" (+{len(ports) - 25})" if len(ports) > 25 else ""
    lines.append("")
    lines.append(f"🌐 Koneksi aktif: <b>{data['connections']}</b>")
    lines.append(f"🔓 Port listen: <code>{h(shown)}{more}</code>")
    for p in data["watch_ports"]:
        lines.append(f"  ✅ port {p} terbuka")
    for p in data["watch_ports_missing"]:
        lines.append(f"  {mark('warn')} port {p} tidak listen")

    if data.get("temperature") is not None:
        lvl = level_from_threshold(data["temperature"], th["temp"]["warn"], th["temp"]["crit"])
        lines.append(f"🌡 Suhu: <b>{data['temperature']}°C</b> {mark(lvl)}")
    else:
        lines.append("🌡 Suhu: ⚪ tidak tersedia")

    if data.get("top_processes"):
        lines.append("")
        lines.append("📊 <b>Proses teratas (CPU)</b>")
        for proc in data["top_processes"]:
            lines.append(f"  • {h(proc['name'])} — CPU {proc['cpu']}% / RAM {proc['mem']}%")

    if not data.get("systemd"):
        lines.append("")
        lines.append("<i>Catatan: systemd tidak aktif — status service dibaca dari proses.</i>")

    status_text = {"ok": "✅ SEMUA NORMAL", "warn": "⚠️ PERLU PERHATIAN", "crit": "❌ KRITIS"}[worst]
    lines.append("")
    lines.append(f"<b>Status: {status_text}</b>")
    text = "\n".join(lines)
    return text, worst


# ------------------------------------------------------------------------ CLI
def run(send: bool = False, cfg: dict | None = None) -> tuple[str, str, dict]:
    cfg = cfg or load_config()
    log.info("Mulai monitoring server")
    data = collect(cfg)
    text, worst = format_report(data, cfg)
    save_report("monitor", text)
    if send:
        require = cfg["bot_token"] and cfg["chat_id"]
        if not require:
            log.error("bot_token/chat_id kosong — laporan tidak dikirim")
        else:
            TelegramClient(cfg["bot_token"], cfg["chat_id"], logger=log).send(text)
    log.info("Monitoring selesai: status=%s cpu=%s ram=%s%%", worst, data["cpu"], data["ram"]["percent"])
    return text, worst, data


def main() -> int:
    parser = argparse.ArgumentParser(description="Modul A — Monitoring Server")
    parser.add_argument("--send", action="store_true", help="kirim hasil ke Telegram")
    parser.add_argument("--json", action="store_true", help="cetak JSON mentah")
    args = parser.parse_args()
    try:
        if args.json:
            print(json.dumps(collect(), indent=2, default=str))
            return 0
        text, worst, _ = run(send=args.send)
        print(text)
        return 0 if worst != "crit" else 2
    except Exception as exc:  # jangan pernah crash keras
        log.exception("Monitoring gagal: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
