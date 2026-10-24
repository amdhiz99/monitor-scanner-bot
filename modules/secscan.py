#!/usr/bin/env python3
"""MODUL B — Security Scan (server & domain/subdomain).

Server:
  - port terbuka (nmap bila tersedia, fallback TCP connect murni Python)
  - konfigurasi dasar rawan (SSH root login, password auth, service terbuka ke publik)
  - update keamanan OS yang tertunda

Domain/subdomain:
  - HTTP dan HTTPS diperiksa TERPISAH: status code, rantai redirect, waktu respons
  - SSL/TLS: masa berlaku sertifikat, issuer, TLS version, cipher lemah
  - header keamanan dasar
Semua temuan diberi tingkat risiko: low / medium / high / critical.

Pemakaian:
    python3 -m modules.secscan server
    python3 -m modules.secscan domain barlve.com www.barlve.com
    python3 -m modules.secscan domain barlve.com --send
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.settings import load_config
from core.tg import TelegramClient
from core.utils import (
    RISK_ORDER,
    get_logger,
    h,
    hostname,
    now_str,
    risk_badge,
    save_report,
)

log = get_logger("secscan")

USER_AGENT = "Mozilla/5.0 (compatible; OrcaRouterMonitor/1.0; +own-infrastructure-check)"
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "medium"),
    ("content-security-policy", "CSP", "low"),
    ("x-frame-options", "X-Frame-Options", "low"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("referrer-policy", "Referrer-Policy", "low"),
]


def sh(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace", stdin=subprocess.DEVNULL,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, str(exc)


def finding(risk: str, title: str, detail: str = "", category: str = "general") -> dict:
    return {"risk": risk.lower(), "title": title, "detail": detail, "category": category}


def worst_risk(items: list[dict]) -> str:
    if not items:
        return "info"
    return sorted(items, key=lambda f: RISK_ORDER.get(f["risk"], 9))[0]["risk"]


def risk_counts(items: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        counts[item["risk"]] = counts.get(item["risk"], 0) + 1
    return counts


# =============================================================== SERVER SCAN
def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def scan_ports_socket(host: str, ports: list[int], timeout: float = 1.5) -> list[int]:
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(64, max(8, len(ports)))) as pool:
        futures = {pool.submit(_port_open, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    open_ports.append(futures[fut])
            except Exception:  # noqa: BLE001 - jangan crash karena satu port
                continue
    return sorted(open_ports)


def nmap_available() -> bool:
    code, _ = sh(["nmap", "--version"], timeout=10)
    return code == 0


def scan_ports_nmap(host: str, cfg: dict) -> tuple[list[int], str]:
    """Pindai port dengan nmap greppable output. Return (ports, keterangan)."""
    scfg = cfg["server_scan"]
    args = ["nmap", "-sT", "-Pn", "-T4", "--host-timeout", "240s"]
    profile = str(scfg.get("nmap_profile", "top200")).lower()
    if profile.startswith("top"):
        args += ["--top-ports", re.sub(r"\D", "", profile) or "200"]
    elif profile == "all":
        args += ["-p-"]
    else:
        args += ["--top-ports", "200"]
    extra = str(scfg.get("nmap_extra_ports", "")).strip()
    if extra:
        args += ["-p", extra]
    args += ["-oG", "-", host]
    code, out = sh(args, timeout=int(scfg.get("timeout", 300)))
    if code != 0 and not out.strip():
        log.warning("nmap gagal (code %s): %s", code, out[:200])
        return [], f"nmap gagal: {out.strip()[:150] or 'tanpa output'}"
    ports: set[int] = set()
    for line in out.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        chunk = line.split("Ports:", 1)[1].split("Ignored State")[0]
        for item in chunk.split(","):
            parts = item.strip().split("/")
            if len(parts) >= 2 and parts[1].strip() == "open" and parts[0].isdigit():
                ports.add(int(parts[0]))
    return sorted(ports), "nmap"


def public_listeners(ports: list[int]) -> list[int]:
    """Port di daftar yang listen di 0.0.0.0/:: (terbuka ke jaringan)."""
    code, out = sh(["ss", "-H", "-ltn"], timeout=10)
    if code != 0:
        return []
    exposed: set[int] = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 4 or ":" not in cols[3]:
            continue
        try:
            port = int(cols[3].rsplit(":", 1)[1])
        except ValueError:
            continue
        if port in ports and ("0.0.0.0" in cols[3] or "::" in cols[3] or "[::]" in cols[3]):
            exposed.add(port)
    return sorted(exposed)


def check_ssh_config() -> list[dict]:
    findings: list[dict] = []
    candidates = [Path("/etc/ssh/sshd_config")] + sorted(
        Path("/etc/ssh/sshd_config.d").glob("*.conf")
    ) if Path("/etc/ssh/sshd_config.d").is_dir() else [Path("/etc/ssh/sshd_config")]
    values: dict[str, str] = {}
    readable = False
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            readable = True
        except OSError:
            continue
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or " " not in line:
                continue
            key, _, val = line.partition(" ")
            key = key.lower()
            if key in {"permitrootlogin", "passwordauthentication",
                       "permitemptypasswords", "x11forwarding", "port"}:
                values[key] = val.strip()

    if not readable:
        return [finding("info", "Konfigurasi SSH tidak terbaca",
                        "Tidak ada akses baca /etc/ssh/sshd_config (jalankan sebagai root untuk cek penuh)",
                        "ssh")]

    root = values.get("permitrootlogin", "")
    if root.lower() in {"yes", "prohibit-password", "without-password"}:
        risk = "high" if root.lower() == "yes" else "low"
        findings.append(finding(risk, "SSH: login root diizinkan",
                                f"PermitRootLogin {root} — sebaiknya 'no' atau 'prohibit-password'",
                                "ssh"))
    pwd = values.get("passwordauthentication", "")
    if pwd.lower() == "yes":
        findings.append(finding("medium", "SSH: autentikasi password aktif",
                                "PasswordAuthentication yes — pertimbangkan key-only",
                                "ssh"))
    if values.get("permitemptypasswords", "").lower() == "yes":
        findings.append(finding("critical", "SSH: password kosong diizinkan",
                                "PermitEmptyPasswords yes", "ssh"))
    if values.get("x11forwarding", "").lower() == "yes":
        findings.append(finding("low", "SSH: X11 forwarding aktif",
                                "X11Forwarding yes", "ssh"))
    if not findings:
        findings.append(finding("info", "Konfigurasi SSH dasar baik",
                                "Root login tidak bebas, password auth tidak dipaksa", "ssh"))
    return findings


def check_pending_updates() -> list[dict]:
    findings: list[dict] = []
    # apt-check: hasil "total;security" (Ubuntu/Debian)
    for cmd, timeout in (
        (["/usr/lib/update-notifier/apt-check"], 60),
        (["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], 90),
    ):
        code, out = sh(cmd, timeout=timeout)
        if code != 0 and not out.strip():
            continue
        if cmd[0].endswith("apt-check"):
            match = re.search(r"(\d+);(\d+)", out)
            if match:
                total, security = int(match.group(1)), int(match.group(2))
                if security > 0:
                    risk = "critical" if security >= 20 else "high" if security >= 5 else "medium"
                    findings.append(finding(risk, f"{security} update keamanan tertunda",
                                            f"Total {total} paket dapat di-upgrade. Jalankan: sudo apt upgrade",
                                            "update"))
                else:
                    findings.append(finding("info", "Tidak ada update keamanan tertunda",
                                            f"{total} paket upgrade non-keamanan (opsional)", "update"))
                return findings
        else:
            sec = re.findall(r"^Inst (\S+).*(security|Security)", out, re.MULTILINE)
            total = len(re.findall(r"^Inst ", out, re.MULTILINE))
            if sec:
                risk = "critical" if len(sec) >= 20 else "high" if len(sec) >= 5 else "medium"
                findings.append(finding(risk, f"{len(sec)} paket keamanan dapat di-upgrade",
                                        "Contoh: " + ", ".join(s[0] for s in sec[:5]), "update"))
            elif total:
                findings.append(finding("low", f"{total} paket dapat di-upgrade",
                                        "Tidak ada yang ditandai security", "update"))
            else:
                findings.append(finding("info", "Sistem sudah pada versi terbaru", "", "update"))
            return findings
    findings.append(finding("info", "Status update tidak dapat dibaca",
                            "Butuh akses apt/dpkg (root) atau paket update-notifier", "update"))
    return findings


def run_server_scan(cfg: dict | None = None, target: str = "127.0.0.1") -> tuple[str, str, dict]:
    cfg = cfg or load_config()
    scfg = cfg["server_scan"]
    started = time.time()
    log.info("Mulai server scan target=%s", target)
    findings: list[dict] = []

    # --- port
    ports: list[int] = []
    engine = "socket"
    if scfg.get("nmap_enabled", True) and nmap_available():
        ports, engine = scan_ports_nmap(target, cfg)
        if engine != "nmap":  # nmap gagal → fallback
            engine = "socket"
    if engine == "socket":
        ports = scan_ports_socket(target, list(scfg.get("socket_fallback_ports", [22, 80, 443])))
    open_ports = ports

    risky_map = {str(k): v for k, v in (scfg.get("risky_ports") or {}).items()}
    exposed = public_listeners(open_ports)
    for port in open_ports:
        risk = risky_map.get(str(port))
        if risk:
            findings.append(finding(risk, f"Port berisiko terbuka: {port}",
                                    "Port ini sebaiknya tidak terekspos ke internet", "port"))
        elif port in exposed:
            findings.append(finding("low", f"Port {port} listen di semua interface",
                                    "Pastikan memang perlu diakses publik", "port"))

    # --- SSH
    if scfg.get("check_ssh_config", True):
        findings.extend(check_ssh_config())

    # --- update
    if scfg.get("check_updates", True):
        findings.extend(check_pending_updates())

    findings = [f for f in findings if f["risk"] != "info"] or findings
    findings.sort(key=lambda f: RISK_ORDER.get(f["risk"], 9))
    worst = worst_risk([f for f in findings if f["risk"] != "info"]) if findings else "info"
    counts = risk_counts(findings)
    data = {
        "target": target,
        "engine": engine,
        "ports": open_ports,
        "exposed": exposed,
        "findings": findings,
        "counts": counts,
        "worst": worst,
        "duration": round(time.time() - started, 1),
    }
    text = format_server_report(data, cfg)
    save_report("scan_server", text)
    log.info("Server scan selesai: %s port terbuka, worst=%s, %.1fs",
             len(open_ports), worst, data["duration"])
    return text, worst, data


def format_server_report(data: dict, cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    lines = [
        "🛡️ <b>SECURITY SCAN — SERVER</b>",
        f"<i>{now_str(cfg.get('timezone_label', 'WIB'))}</i>",
        f"Host: <code>{h(hostname())}</code> · Target: <code>{h(data['target'])}</code>",
        f"Mesin scan port: <i>{h(data['engine'])}</i> · durasi {data['duration']}s",
        "",
        f"🔓 <b>Port terbuka ({len(data['ports'])})</b>",
    ]
    if data["ports"]:
        lines.append(f"<code>{h(', '.join(str(p) for p in data['ports'][:40]))}</code>")
        if len(data["ports"]) > 40:
            lines.append(f"<i>... (+{len(data['ports']) - 40} lainnya)</i>")
        if data["exposed"]:
            lines.append(f"⚠️ Listen di semua interface: <code>{h(', '.join(str(p) for p in data['exposed']))}</code>")
    else:
        lines.append("Tidak ada port terbuka terdeteksi (atau host memblokir probe)")

    real = [f for f in data["findings"] if f["risk"] != "info"]
    info = [f for f in data["findings"] if f["risk"] == "info"]
    lines.append("")
    lines.append(f"🚨 <b>Temuan ({len(real)})</b>")
    if real:
        for item in real:
            lines.append("")
            lines.append(f"{risk_badge(item['risk'])} — <b>{h(item['title'])}</b>")
            if item["detail"]:
                lines.append(f"  <i>{h(item['detail'])}</i>")
    else:
        lines.append("Tidak ada temuan berisiko ✅")
    if info:
        lines.append("")
        lines.append("ℹ️ <b>Catatan</b>")
        for item in info:
            lines.append(f"  • {h(item['title'])}" + (f" — <i>{h(item['detail'])}</i>" if item["detail"] else ""))

    counts = data["counts"]
    lines.append("")
    lines.append(
        f"<b>Ringkasan:</b> 🔴 {counts.get('critical', 0)} · 🟠 {counts.get('high', 0)} · "
        f"🟡 {counts.get('medium', 0)} · 🔵 {counts.get('low', 0)}"
    )
    verdict = {
        "critical": "❌ KRITIS — perlu tindakan segera",
        "high": "⚠️ RISIKO TINGGI",
        "medium": "⚠️ PERLU PERHATIAN",
        "low": "✅ RISIKO RENDAH",
        "info": "✅ TIDAK ADA TEMUAN BERISIKO",
    }.get(data["worst"], "✅ AMAN")
    lines.append(f"<b>Status: {verdict}</b>")
    return "\n".join(lines)


# =============================================================== DOMAIN SCAN
def normalize_host(raw: str) -> str:
    host = (raw or "").strip().strip(",;")
    if "://" in host:
        host = urllib.parse.urlsplit(host).hostname or host
    host = host.split("/")[0].split("?")[0].split("@")[-1]
    if host.count(":") == 1:  # host:port
        host = host.split(":")[0]
    return host.strip().lower()


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        log.warning("DNS gagal untuk %s: %s", host, exc)
        return []
    return sorted({info[4][0] for info in infos})


def tcp_connect(host: str, port: int, timeout: int) -> socket.socket:
    """Koneksi TCP yang memprioritaskan IPv4 (WSL/host tanpa rute IPv6)."""
    errors: list[str] = []
    for family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            errors.append(str(exc))
            continue
        for fam, socktype, proto, _, sockaddr in infos:
            sock = None
            try:
                sock = socket.socket(fam, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                errors.append(str(exc))
                if sock is not None:
                    sock.close()
    raise OSError("; ".join(errors[-2:]) or "tidak dapat terhubung")


def _connect_ipv4(self) -> None:  # monkey-patch untuk http.client
    infos = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_STREAM)
    last: Exception | None = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            self.sock = socket.socket(family, socktype, proto)
            self.sock.settimeout(self.timeout)
            self.sock.connect(sockaddr)
            return
        except OSError as exc:
            last = exc
            try:
                if self.sock:
                    self.sock.close()
            except OSError:
                pass
            self.sock = None
    raise last or OSError("tidak ada alamat IPv4 yang bisa dihubungi")


class _HttpV4(http.client.HTTPConnection):
    def connect(self):
        _connect_ipv4(self)


class _HttpsV4(http.client.HTTPSConnection):
    def connect(self):
        _connect_ipv4(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _http_probe_once(host: str, scheme: str, timeout: int, max_redirects: int) -> dict:
    """Satu percobaan GET dengan redirect ditelusuri satu per satu."""
    result = {
        "scheme": scheme,
        "reachable": False,
        "status": None,
        "chain": [],
        "final_url": None,
        "headers": {},
        "error": None,
        "title": "",
        "elapsed": 0.0,
    }
    port = 443 if scheme == "https" else 80
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # probe tetap jalan walau sertifikat bermasalah

    path = "/"
    current_host = host
    visited: set[str] = set()
    started = time.perf_counter()
    try:
        for _ in range(max_redirects + 1):
            key = f"{scheme}://{current_host}{path}"
            if key in visited:
                result["error"] = "redirect loop terdeteksi"
                break
            visited.add(key)

            def build_conn(v4: bool):
                if scheme == "https":
                    cls = _HttpsV4 if v4 else http.client.HTTPSConnection
                    return cls(current_host, port, timeout=timeout, context=context)
                cls = _HttpV4 if v4 else http.client.HTTPConnection
                return cls(current_host, port, timeout=timeout)

            def fetch(conn):
                conn.request("GET", path, headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                })
                response = conn.getresponse()
                return response, {k.lower(): v for k, v in response.getheaders()}, \
                    response.read(60000).decode("utf-8", "replace")

            conn = build_conn(v4=True)
            try:
                try:
                    resp, headers, body = fetch(conn)
                except OSError:
                    # host hanya punya IPv6 / IPv4 gagal → coba resolver default
                    conn.close()
                    conn = build_conn(v4=False)
                    resp, headers, body = fetch(conn)
            finally:
                conn.close()

            status = resp.status
            result["reachable"] = True
            result["status"] = status
            result["headers"] = headers
            result["final_url"] = key
            link = {
                "url": key,
                "status": status,
                "location": headers.get("location", ""),
            }
            result["chain"].append(link)
            if status not in (301, 302, 303, 307, 308):
                match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                if match:
                    result["title"] = re.sub(r"\s+", " ", match.group(1)).strip()[:80]

            if status in (301, 302, 303, 307, 308) and headers.get("location"):
                target = urllib.parse.urljoin(key, headers["location"])
                parts = urllib.parse.urlsplit(target)
                if parts.scheme not in {"http", "https"}:
                    break
                scheme = parts.scheme
                current_host = parts.hostname or current_host
                port = parts.port or (443 if scheme == "https" else 80)
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                continue
            break
    except ssl.SSLError as exc:
        result["error"] = f"TLS error: {getattr(exc, 'reason', exc)}"
    except socket.timeout:
        result["error"] = "timeout"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    except http.client.HTTPException as exc:
        result["error"] = f"HTTP error: {type(exc).__name__}: {exc}"
    result["elapsed"] = round((time.perf_counter() - started) * 1000)
    if result["chain"]:
        result["initial_status"] = result["chain"][0]["status"]
        result["redirected"] = len(result["chain"]) > 1
        result["final_scheme"] = result["chain"][-1]["url"].split("://", 1)[0]
    else:
        result["initial_status"] = None
        result["redirected"] = False
        result["final_scheme"] = scheme
    return result


def http_probe(host: str, scheme: str, timeout: int, max_redirects: int,
               attempts: int = 2) -> dict:
    """Probe HTTP/HTTPS dengan retry ringan untuk kegagalan koneksi sesaat."""
    result = _http_probe_once(host, scheme, timeout, max_redirects)
    tries = 1
    while not result["reachable"] and tries < attempts:
        tries += 1
        log.info("Probe %s://%s gagal (%s), percobaan ulang %s/%s",
                 scheme, host, result.get("error"), tries, attempts)
        time.sleep(0.7)
        result = _http_probe_once(host, scheme, timeout, max_redirects)
    result["attempts"] = tries
    return result


def _cert_meta_from_pem(pem: bytes) -> dict:
    """Baca tanggal/issuer/subject dari sertifikat walau verifikasi gagal (pakai openssl)."""
    meta: dict = {"not_after": None, "issuer": "", "subject": "", "san": []}
    import tempfile

    tmp = Path(tempfile.mkstemp(suffix=".pem", prefix="cert_", dir="/tmp")[1])
    try:
        tmp.write_bytes(pem)
        code, out = sh(["openssl", "x509", "-in", str(tmp), "-noout",
                        "-enddate", "-subject", "-issuer", "-ext", "subjectAltName"], timeout=10)
        if not out.strip():
            return meta
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("notAfter="):
                raw = line.split("=", 1)[1]
                meta["raw_not_after"] = raw
                try:
                    expiry = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    meta["not_after"] = expiry.strftime("%Y-%m-%d %H:%M:%S UTC")
                    meta["days_left"] = (expiry - datetime.now(timezone.utc)).days
                except ValueError:
                    meta["not_after"] = raw
            elif line.startswith("subject="):
                meta["subject"] = line.split("=", 1)[1].strip()
            elif line.startswith("issuer="):
                meta["issuer"] = line.split("=", 1)[1].strip()
            elif line.startswith("DNS:"):
                meta["san"] = [item.split(":", 1)[1].strip() for item in line.split(",") if item.strip().startswith("DNS:")]
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return meta


def tls_details(host: str, timeout: int) -> dict:
    """Ambil detail TLS: validitas, issuer, versi, cipher. Tidak pernah raise."""
    info = {
        "ok": False, "verified": False, "error": None,
        "not_after": None, "days_left": None, "issuer": "", "subject": "",
        "san": [], "tls_version": None, "cipher": None, "bits": None, "protocol": None,
    }

    # 1) handshake terverifikasi (kasus normal)
    try:
        ctx = ssl.create_default_context()
        sock = tcp_connect(host, 443, timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            info["ok"] = info["verified"] = True
            info["tls_version"] = info["protocol"] = tls.version()
            cipher = tls.cipher()
            if cipher:
                info["cipher"], info["bits"] = cipher[0], cipher[2]
            cert = tls.getpeercert() or {}
            if cert:
                info["not_after"] = cert.get("notAfter")
                info["issuer"] = ", ".join(
                    f"{k}={v}" for rdn in cert.get("issuer", ()) for k, v in rdn
                )
                info["subject"] = ", ".join(
                    f"{k}={v}" for rdn in cert.get("subject", ()) for k, v in rdn
                )
                info["san"] = [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"]
                try:
                    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") \
                        .replace(tzinfo=timezone.utc)
                    info["days_left"] = (expiry - datetime.now(timezone.utc)).days
                except (KeyError, ValueError):
                    pass
        return info
    except ssl.SSLCertVerificationError as exc:
        info["ok"] = True
        info["verified"] = False
        info["error"] = exc.verify_message or str(exc)
        log.warning("Sertifikat %s tidak valid: %s", host, info["error"])
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        log.warning("TLS handshake %s gagal: %s", host, info["error"])
        return info

    # 2) tetap ambil metadata sertifikat (tanggal/issuer) tanpa verifikasi
    try:
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        sock = tcp_connect(host, 443, timeout)
        with raw_ctx.wrap_socket(sock, server_hostname=host) as tls:
            info["tls_version"] = info["protocol"] = tls.version()
            cipher = tls.cipher()
            if cipher:
                info["cipher"], info["bits"] = cipher[0], cipher[2]
            der = tls.getpeercert(binary_form=True)
        if der:
            pem = ssl.DER_cert_to_PEM_cert(der).encode()
            meta = _cert_meta_from_pem(pem)
            for key in ("not_after", "days_left", "issuer", "subject", "san"):
                if meta.get(key):
                    info[key] = meta[key]
    except (ssl.SSLError, socket.timeout, OSError, ValueError) as exc:
        log.warning("Metadata sertifikat %s tidak terbaca: %s", host, exc)
    return info


def probe_legacy(host: str, timeout: int, ciphers: list[str]) -> dict:
    """Cek protokol/cipher lemah dengan openssl s_client (opsional, tidak fatal)."""
    res = {"tls10": False, "tls11": False, "weak_cipher": False, "notes": []}
    if not sh(["openssl", "version"], timeout=5)[0] == 0:
        return res
    probes = [
        ("tls10", ["-tls1"]),
        ("tls11", ["-tls1_1"]),
    ]
    for key, args in probes:
        code, out = sh(
            ["openssl", "s_client", "-4", "-connect", f"{host}:443", "-servername", host,
             *args, "-no_ign_eof"], timeout=max(8, timeout),
        )
        text = out.lower()
        if "protocol  : tlsv1" in text.replace("tlsv1.1", "tlsv1") or re.search(r"protocol\s*:\s*tlsv1(\.0)?\b", text):
            if "alert" not in text and "handshake failure" not in text and "no protocols available" not in text:
                res[key] = True
    cipher_str = ":".join(ciphers) if ciphers else "3DES:RC4:NULL:EXPORT"
    code, out = sh(
        ["openssl", "s_client", "-4", "-connect", f"{host}:443", "-servername", host,
         "-cipher", f"{cipher_str}:@SECLEVEL=0", "-no_ign_eof"], timeout=max(8, timeout),
    )
    text = out.lower()
    if re.search(r"cipher\s*:\s*\S", text) and "handshake failure" not in text:
        chosen = re.search(r"cipher\s*:\s*(\S+)", text)
        res["weak_cipher"] = True
        res["notes"].append(chosen.group(1) if chosen else "cipher lemah diterima")
    return res


def scan_domain(raw: str, cfg: dict | None = None, deep: bool = True) -> tuple[str, str, dict]:
    cfg = cfg or load_config()
    dcfg = cfg["domain_scan"]
    host = normalize_host(raw)
    timeout = int(dcfg.get("timeout", 10))
    findings: list[dict] = []
    started = time.time()
    log.info("Mulai domain scan: %s", host)

    data = {"host": host, "ips": [], "http": None, "https": None, "tls": {},
            "findings": [], "worst": "info", "counts": {}, "duration": 0.0}

    if not host or not re.match(r"^[a-z0-9._-]+$", host):
        text = format_domain_report(
            {**data, "host": raw, "findings": [finding("medium", "Input tidak valid",
                                                       "Gunakan format domain, mis. contoh.com", "input")],
             "worst": "medium", "counts": risk_counts([finding("medium", "x")])}, cfg)
        return text, "medium", data

    ips = resolve_host(host)
    data["ips"] = ips
    if not ips:
        findings.append(finding("high", "Domain tidak dapat di-resolve",
                                f"DNS gagal untuk {host} — cek ejaan atau DNS record", "dns"))
        data.update(findings=findings, worst="high", counts=risk_counts(findings))
        text = format_domain_report(data, cfg)
        save_report("scan_domain", text)
        return text, "high", data

    # --- probe HTTP & HTTPS terpisah (paralel)
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_http = pool.submit(http_probe, host, "http", timeout, int(dcfg.get("max_redirects", 5)))
        fut_https = pool.submit(http_probe, host, "https", timeout, int(dcfg.get("max_redirects", 5)))
        http_res = fut_http.result()
        https_res = fut_https.result()
    data["http"], data["https"] = http_res, https_res

    # --- TLS
    if https_res["reachable"] or https_res["status"]:
        tls = tls_details(host, timeout)
        if deep:
            tls.update(probe_legacy(host, timeout, list(dcfg.get("weak_ciphers", []))))
        data["tls"] = tls
    tls = data.get("tls") or {}

    # ---------------------------------------------------------- findings
    if http_res["reachable"] and not https_res["reachable"]:
        findings.append(finding("high", "HTTPS tidak dapat diakses",
                                f"HTTP merespons {http_res['status']} tetapi HTTPS gagal: {https_res['error'] or 'tidak ada respons'}",
                                "availability"))
    elif not http_res["reachable"] and https_res["reachable"]:
        findings.append(finding("low", "HTTP tidak aktif, HTTPS aktif",
                                f"HTTP: {http_res['error'] or 'tidak merespons'}", "availability"))
    elif not http_res["reachable"] and not https_res["reachable"]:
        findings.append(finding("high", "Domain tidak merespons di HTTP maupun HTTPS",
                                f"HTTP: {http_res['error']} | HTTPS: {https_res['error']}", "availability"))

    if http_res["reachable"]:
        https_redirect = any(
            link["location"].lower().startswith("https://") for link in http_res["chain"]
        )
        if not https_redirect:
            findings.append(finding("medium", "HTTP tidak redirect ke HTTPS",
                                    f"Status {http_res['status']} — trafik tetap bisa plaintext", "tls"))
        if http_res["status"] and 500 <= http_res["status"] < 600:
            findings.append(finding("medium", f"HTTP error {http_res['status']}",
                                    "Server mengembalikan error pada halaman utama", "availability"))

    if https_res["reachable"]:
        if https_res["status"] and 500 <= https_res["status"] < 600:
            findings.append(finding("medium", f"HTTPS error {https_res['status']}",
                                    "Server mengembalikan error pada halaman utama", "availability"))
    if tls.get("error"):
        risk = "critical" if "expired" in tls["error"].lower() else "high"
        findings.append(finding(risk, "Sertifikat TLS tidak valid", tls["error"], "tls"))

    days_left = tls.get("days_left")
    warn_days = int(dcfg.get("cert_warn_days", 14))
    crit_days = int(dcfg.get("cert_crit_days", 7))
    if days_left is not None:
        if days_left < 0:
            findings.append(finding("critical", "Sertifikat TLS sudah kedaluwarsa",
                                    f"Kedaluwarsa {abs(days_left)} hari lalu (notAfter {tls.get('not_after')})", "tls"))
        elif days_left <= crit_days:
            findings.append(finding("critical", f"Sertifikat TLS tinggal {days_left} hari",
                                    f"Segera perbarui (notAfter {tls.get('not_after')})", "tls"))
        elif days_left <= warn_days:
            findings.append(finding("medium", f"Sertifikat TLS tinggal {days_left} hari",
                                    f"Jadwalkan perpanjangan (notAfter {tls.get('not_after')})", "tls"))

    version = str(tls.get("tls_version") or tls.get("protocol") or "")
    if version in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
        findings.append(finding("high", f"Versi TLS lemah: {version}",
                                "Gunakan TLS 1.2+", "tls"))
    if tls.get("tls10") or tls.get("tls11"):
        weak = "TLS1.0" if tls.get("tls10") else "TLS1.1"
        findings.append(finding("high", f"Server masih menerima {weak}",
                                "Protokol usang, rentan downgrade/BEAST", "tls"))
    if tls.get("weak_cipher"):
        findings.append(finding("high", "Cipher lemah diterima",
                                ", ".join(tls.get("notes") or []) or "3DES/RC4/NULL", "tls"))

    if dcfg.get("check_security_headers", True) and https_res["reachable"]:
        headers = https_res["headers"]
        missing = [(name, label, risk) for name, label, risk in SECURITY_HEADERS
                   if name not in headers]
        for name, label, risk in missing:
            findings.append(finding(risk, f"Header keamanan hilang: {label}",
                                    f"Tambahkan header {name}", "header"))

    if https_res["reachable"] and https_res["headers"].get("server"):
        banner = https_res["headers"]["server"]
        if re.search(r"\d+\.\d+", banner):
            findings.append(finding("low", "Versi server terekspos",
                                    f"Server: {banner} — pertimbangkan menyembunyikan versi", "header"))

    if not findings:
        findings.append(finding("info", "Tidak ada masalah dasar ditemukan",
                                "Status HTTP/HTTPS dan TLS dalam kondisi baik", "general"))

    real = [f for f in findings if f["risk"] != "info"]
    findings.sort(key=lambda f: RISK_ORDER.get(f["risk"], 9))
    data.update(
        findings=findings,
        counts=risk_counts(findings),
        worst=worst_risk(real) if real else "info",
        duration=round(time.time() - started, 1),
    )
    text = format_domain_report(data, cfg)
    save_report("scan_domain", text)
    log.info("Domain scan selesai: %s worst=%s %.1fs", host, data["worst"], data["duration"])
    return text, data["worst"], data


def _chain_text(chain: list[dict]) -> str:
    if not chain:
        return "—"
    parts = []
    for link in chain:
        if link["location"]:
            parts.append(f"{link['status']} → {link['location']}")
        else:
            parts.append(str(link["status"]))
    return " | ".join(parts)


def format_domain_report(data: dict, cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    host = data["host"]
    lines = [
        f"🌐 <b>SECURITY SCAN — DOMAIN</b>",
        f"<i>{now_str(cfg.get('timezone_label', 'WIB'))}</i>",
        f"Domain: <b>{h(host)}</b>",
        f"IP: <code>{h(', '.join(data['ips']) if data['ips'] else 'tidak ada')}</code>",
    ]
    icon = {"ok": "✅", "warn": "⚠️", "crit": "❌"}
    for scheme, key in (("HTTP", "http"), ("HTTPS", "https")):
        res = data.get(key)
        lines.append("")
        if not res:
            lines.append(f"{icon['crit']} <b>{scheme}</b>: tidak diperiksa")
            continue
        if not res["reachable"]:
            lines.append(f"{icon['crit']} <b>{scheme}</b>: TIDAK DAPAT DIAKSES")
            lines.append(f"  <i>{h(res['error'] or 'tidak ada respons')}</i>")
            continue
        status = res["status"]
        initial = res.get("initial_status")
        mark = "✅" if status and status < 400 else "⚠️" if status and status < 500 else "❌"
        if initial and initial != status:
            lines.append(f"{mark} <b>{scheme}</b>: status <b>{initial} → {status}</b> · {res['elapsed']} ms")
        else:
            lines.append(f"{mark} <b>{scheme}</b>: status <b>{status}</b> · {res['elapsed']} ms")
        if res["title"]:
            lines.append(f"  Judul: <i>{h(res['title'])}</i>")
        lines.append(f"  Redirect: <code>{h(_chain_text(res['chain']))}</code>")
        server = res["headers"].get("server")
        if server:
            lines.append(f"  Server: <code>{h(server)}</code>")

    # Bandingkan HTTP vs HTTPS secara eksplisit
    http_res, https_res = data.get("http"), data.get("https")
    if http_res and https_res and http_res["reachable"] and https_res["reachable"]:
        h_init = http_res.get("initial_status")
        s_init = https_res.get("initial_status")
        lines.append("")
        if http_res.get("redirected") and http_res.get("final_scheme") == "https":
            lines.append(f"⚖️ <b>HTTP dialihkan ke HTTPS</b> ({h_init} → {https_res['status']})")
        elif h_init != s_init:
            lines.append(f"⚖️ <b>Perbedaan:</b> HTTP {h_init} vs HTTPS {s_init}")
        else:
            lines.append(f"⚖️ <b>HTTP & HTTPS sama</b> (status {h_init})")

    tls = data.get("tls") or {}
    if tls:
        lines.append("")
        lines.append("🔒 <b>SSL/TLS</b>")
        if not tls.get("ok") and tls.get("error"):
            lines.append(f"  ❌ Tidak dapat handshake: <i>{h(tls['error'])}</i>")
        days = tls.get("days_left")
        if days is not None:
            emoji = "✅" if days > int(cfg["domain_scan"].get("cert_warn_days", 14)) else "⚠️" if days > 0 else "❌"
            lines.append(f"  {emoji} Sertifikat berlaku: <b>{days} hari</b> lagi")
            lines.append(f"  <i>notAfter: {h(tls.get('not_after'))}</i>")
        elif not tls.get("error"):
            lines.append("  ⚪ Masa berlaku sertifikat tidak terbaca")
        if tls.get("issuer"):
            lines.append(f"  Issuer: <i>{h(tls['issuer'])}</i>")
        if tls.get("tls_version") or tls.get("protocol"):
            lines.append(f"  Protokol: <b>{h(tls.get('tls_version') or tls.get('protocol'))}</b>")
        if tls.get("cipher"):
            lines.append(f"  Cipher: <code>{h(tls['cipher'])}</code>" +
                         (f" ({tls.get('bits')} bit)" if tls.get("bits") else ""))
        legacy = []
        if tls.get("tls10"):
            legacy.append("TLS1.0")
        if tls.get("tls11"):
            legacy.append("TLS1.1")
        if tls.get("weak_cipher"):
            legacy.append("cipher lemah")
        if legacy:
            lines.append(f"  ⚠️ Menerima: {h(', '.join(legacy))}")
        if tls.get("san"):
            lines.append(f"  SAN: <code>{h(', '.join(tls['san'][:6]))}</code>")

    real = [f for f in data["findings"] if f["risk"] != "info"]
    info = [f for f in data["findings"] if f["risk"] == "info"]
    lines.append("")
    lines.append(f"🚨 <b>Temuan ({len(real)})</b>")
    if real:
        for item in real:
            lines.append("")
            lines.append(f"{risk_badge(item['risk'])} — <b>{h(item['title'])}</b>")
            if item["detail"]:
                lines.append(f"  <i>{h(item['detail'])}</i>")
    else:
        lines.append("Tidak ada temuan berisiko ✅")
    if info:
        for item in info:
            lines.append(f"ℹ️ {h(item['title'])}" + (f" — <i>{h(item['detail'])}</i>" if item["detail"] else ""))

    counts = data.get("counts") or {}
    lines.append("")
    lines.append(
        f"<b>Ringkasan:</b> 🔴 {counts.get('critical', 0)} · 🟠 {counts.get('high', 0)} · "
        f"🟡 {counts.get('medium', 0)} · 🔵 {counts.get('low', 0)}"
    )
    verdict = {
        "critical": "❌ KRITIS", "high": "❗ RISIKO TINGGI",
        "medium": "⚠️ PERLU PERHATIAN", "low": "✅ RISIKO RENDAH", "info": "✅ AMAN",
    }.get(data.get("worst", "info"), "✅ AMAN")
    lines.append(f"<b>Status: {verdict}</b> · durasi {data.get('duration', 0)}s")
    return "\n".join(lines)


def run_domain_scan(domains: list[str], cfg: dict | None = None, deep: bool = True) -> tuple[str, str, dict]:
    """Scan beberapa domain sekaligus; kembalikan satu pesan gabungan."""
    cfg = cfg or load_config()
    cfg.setdefault("domain_scan", {}).setdefault("subdomains", [])
    texts: list[str] = []
    worst_all = "info"
    results = []
    for raw in domains:
        text, worst, data = scan_domain(raw, cfg, deep=deep)
        texts.append(text)
        results.append(data)
        if RISK_ORDER.get(worst, 9) < RISK_ORDER.get(worst_all, 9):
            worst_all = worst
    combined = "\n\n" + ("─" * 18) + "\n\n"
    return combined.join(texts), worst_all, {"domains": results}


# ------------------------------------------------------------------------ CLI
def main() -> int:
    parser = argparse.ArgumentParser(description="Modul B — Security Scan")
    sub = parser.add_subparsers(dest="mode", required=True)
    p_server = sub.add_parser("server", help="scan server lokal")
    p_server.add_argument("--target", default="127.0.0.1")
    p_server.add_argument("--send", action="store_true")
    p_domain = sub.add_parser("domain", help="scan domain/subdomain")
    p_domain.add_argument("domains", nargs="*", help="domain (kosong = pakai config)")
    p_domain.add_argument("--send", action="store_true")
    p_domain.add_argument("--fast", action="store_true", help="lewati probe protokol lama")
    args = parser.parse_args()

    cfg = load_config()
    try:
        if args.mode == "server":
            text, worst, _ = run_server_scan(cfg, target=args.target)
        else:
            domains = args.domains or cfg["domain_scan"].get("subdomains", [])
            if not domains:
                print("Tidak ada domain. Berikan argumen atau isi domain_scan.subdomains.", file=sys.stderr)
                return 1
            text, worst, _ = run_domain_scan(domains, cfg, deep=not args.fast)
        print(text)
        if args.send:
            TelegramClient(cfg["bot_token"], cfg["chat_id"], logger=log).send(text)
        return 0 if worst not in {"critical"} else 2
    except Exception as exc:  # noqa: BLE001 - CLI tidak boleh crash
        log.exception("Scan gagal: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
