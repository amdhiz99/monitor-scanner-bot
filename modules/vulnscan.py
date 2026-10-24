#!/usr/bin/env python3
"""MODUL C — Deep Scan: CVE + OWASP Top 10 + verifikasi eksploitasi (read-only).

Empat lapis pemeriksaan:

1. FINGERPRINT  versi komponen yang benar-benar terpasang (PHP, Node, nginx,
                Apache, OpenSSL, kernel, database, Redis) dari lokal maupun header.
2. CVE          tiga sumber, semuanya data nyata:
                - NVD API 2.0 exact-version (virtualMatchString CPE) → CVE untuk
                  versi persis yang terpasang
                - NVD keyword + severity CRITICAL/HIGH untuk produk tsb (headline
                  "CVE terbaru"), diurutkan tanggal terbit
                - apt: paket dengan update keamanan tertunda (otoritatif untuk
                  paket yang diinstal)
                - nuclei: template cve/exposures/misconfig/owasp (maintained)
3. OWASP        A01–A10 dengan probe aman: file sensitif (.git/.env/phpinfo/
                server-status), directory listing, metode HTTP (OPTIONS/TRACE),
                refleksi canary (indikator XSS), header & TLS (A02/A05).
4. VERIFIKASI   hanya read-only, tanpa payload perusak dan tanpa brute force:
                Redis/Memcached/Docker API/Elasticsearch tanpa autentikasi
                (PING/INFO/stats/GET saja), pembuktian file bocor (ambil
                potongan isi), bukan menulis atau mengubah data.

Tidak ada: SQLi weaponized, RCE, brute force password, DoS, upload shell.
Semua target WAJIB milik sendiri.

Pemakaian:
    python3 -m modules.vulnscan --local
    python3 -m modules.vulnscan --domain barlve.com
    python3 -m modules.vulnscan --local --domain barlve.com --send
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.settings import load_config
from core.tg import TelegramClient
from core.utils import (
    REPORT_DIR,
    RISK_ORDER,
    get_logger,
    h,
    now_str,
    risk_badge,
    save_report,
)
from modules import secscan

log = get_logger("vulnscan")

CACHE_FILE = REPORT_DIR / "cve_cache.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# vendor:product untuk CPE NVD. Satu produk bisa punya beberapa CPE resmi
# (contoh: nginx dipindah ke vendor "f5" sejak 2024, yang lama tetap dicoba).
CPE_MAP = {
    "php": [("php", "php")],
    "nodejs": [("nodejs", "node.js")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "apache": [("apache", "http_server")],
    "openssl": [("openssl", "openssl")],
    "python": [("python", "python")],
    "mysql": [("oracle", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "redis": [("redis", "redis")],
    "kernel": [("linux", "linux_kernel")],
    "docker": [("docker", "docker")],
}

# kategori OWASP Top 10 (2021) untuk pelabelan temuan
OWASP = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components",
    "A07": "A07 Identification & Auth Failures",
    "A08": "A08 Software & Data Integrity",
    "A09": "A09 Logging & Monitoring Failures",
    "A10": "A10 SSRF",
}


def sh(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace", stdin=subprocess.DEVNULL)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, str(exc)


def finding(risk: str, title: str, detail: str = "", owasp: str = "",
            source: str = "active") -> dict:
    return {"risk": risk.lower(), "title": title, "detail": detail,
            "owasp": owasp, "source": source}


# ==================================================================== CACHE
def _load_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")
    except OSError as exc:
        log.warning("cache CVE tidak tersimpan: %s", exc)


# ================================================================= NVD API
def nvd_request(params: dict, cfg: dict) -> dict:
    """GET NVD API 2.0 dengan cache 24 jam + throttle (5 req/30s tanpa API key)."""
    dcfg = cfg["deep_scan"]["nvd"]
    cache = _load_cache()
    key = urllib.parse.urlencode(sorted(params.items()))
    ttl = timedelta(hours=float(dcfg.get("cache_hours", 24)))
    entry = cache.get(key)
    if entry:
        try:
            ts = datetime.fromisoformat(entry["ts"])
            if datetime.now(timezone.utc) - ts < ttl:
                log.info("NVD cache hit: %s", key[:80])
                return entry["data"]
        except (KeyError, ValueError):
            pass

    url = f"{NVD_API}?{key}"
    headers = {"User-Agent": "OrcaRouter-DeepScan/1.0"}
    api_key = str(dcfg.get("api_key", "")).strip()
    if api_key:
        headers["apiKey"] = api_key
    timeout = int(dcfg.get("timeout", 25))

    data: dict = {}
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503):
                wait = 6 * attempt
                log.warning("NVD %s (rate limit) — tunggu %ss", exc.code, wait)
                time.sleep(wait)
                continue
            log.warning("NVD HTTP %s untuk %s", exc.code, key[:80])
            return {}
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            log.warning("NVD gagal (%s) percobaan %s: %s", type(exc).__name__, attempt, exc)
            time.sleep(3 * attempt)

    if data and "vulnerabilities" in data:
        cache[key] = {"ts": datetime.now(timezone.utc).isoformat(), "data": data}
        _save_cache(cache)
        if not api_key:
            time.sleep(6.5)  # hormati rate limit publik
    return data


def _cvss(cve: dict) -> tuple[str, float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            sev = (data.get("baseSeverity") or metric.get("baseSeverity") or "").upper()
            score = data.get("baseScore")
            if sev or score is not None:
                if not sev and score is not None:
                    sev = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                           else "MEDIUM" if score >= 4 else "LOW")
                return sev or "UNKNOWN", float(score or 0)
    return "UNKNOWN", 0.0


def _summarize_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    sev, score = _cvss(cve)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("value", "").startswith("CWE"):
                cwes.append(d["value"])
    return {
        "id": cve.get("id", "?"),
        "risk": sev.lower() if sev.lower() in RISK_ORDER else "medium",
        "score": score,
        "published": (cve.get("published") or "")[:10],
        "summary": re.sub(r"\s+", " ", desc)[:220],
        "cwe": sorted(set(cwes))[:3],
    }


def _vtuple(version: str) -> tuple[int, ...]:
    """Ubah '8.3.35' / '1.24.0' / '6.6.87.2' jadi tuple angka untuk dibandingkan."""
    parts: list[int] = []
    for chunk in re.split(r"[.\-_+]", (version or "").strip().lower()):
        match = re.match(r"(\d+)", chunk)
        if not match:
            break
        parts.append(int(match.group(1)))
    return tuple(parts)


def _vcmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def _range_match(criteria: str, installed: tuple[int, ...], rule: dict) -> tuple[bool, str]:
    """Cek satu cpeMatch (versi eksplisit atau rentang) terhadap versi terpasang."""
    fields = criteria.split(":")
    cpe_version = fields[5] if len(fields) > 5 else "*"
    inst_str = ".".join(str(x) for x in installed)
    if cpe_version not in ("*", "-", ""):
        ok = _vcmp(_vtuple(cpe_version), installed) == 0
        return ok, cpe_version
    start_inc = rule.get("versionStartIncluding")
    start_exc = rule.get("versionStartExcluding")
    end_inc = rule.get("versionEndIncluding")
    end_exc = rule.get("versionEndExcluding")
    ok = True
    if start_inc and _vcmp(installed, _vtuple(start_inc)) < 0:
        ok = False
    if start_exc and _vcmp(installed, _vtuple(start_exc)) <= 0:
        ok = False
    if end_inc and _vcmp(installed, _vtuple(end_inc)) > 0:
        ok = False
    if end_exc and _vcmp(installed, _vtuple(end_exc)) >= 0:
        ok = False
    if ok and not any((start_inc, start_exc, end_inc, end_exc)):
        ok = False  # wildcard tanpa batas = berlaku untuk semua versi
    bounds = []
    if start_inc:
        bounds.append(f">={start_inc}")
    if start_exc:
        bounds.append(f">{start_exc}")
    if end_inc:
        bounds.append(f"<={end_inc}")
    if end_exc:
        bounds.append(f"<{end_exc}")
    return ok, (" ".join(bounds) or inst_str)


def _affected_range(cve_obj: dict, product: str, installed: str) -> str | None:
    """Kembalikan rentang versi yang terdampak bila versi terpasang termasuk, else None."""
    if product not in CPE_MAP:
        return None
    installed_t = _vtuple(installed)
    if not installed_t:
        return None
    needles = [f":{vendor}:{name}:" for vendor, name in CPE_MAP[product]]
    for conf in cve_obj.get("configurations", []):
        for node in conf.get("nodes", []):
            for rule in node.get("cpeMatch", []):
                criteria = rule.get("criteria") or ""
                if not any(needle in criteria for needle in needles):
                    continue
                if rule.get("vulnerable") is False:
                    continue
                ok, bounds = _range_match(criteria, installed_t, rule)
                if ok:
                    return bounds
    return None


def watch_cves(watchlist: list[str], stack: list[dict], cfg: dict) -> tuple[list[dict], list[dict]]:
    """Cek CVE tertentu (opsional) terhadap stack yang terdeteksi.

    Berguna untuk CVE yang belum masuk jendela NVD harian, atau yang ingin Anda
    pantau eksplisit. Rentang versi NVD tetap dievaluasi, jadi hasilnya
    "berdampak" atau "tidak berdampak", bukan sekadar daftar CVE.
    """
    findings: list[dict] = []
    detail: list[dict] = []
    seen: set[str] = set()
    for raw in watchlist or []:
        cid = str(raw).strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cid) or cid in seen:
            continue
        seen.add(cid)
        data = nvd_request({"cveId": cid}, cfg)
        entries = data.get("vulnerabilities", [])
        if not entries:
            detail.append({"id": cid, "status": "tidak ditemukan di NVD"})
            continue
        entry = entries[0]
        cve = entry["cve"]
        summary = _summarize_cve(entry)
        hit = None
        for item in stack:
            if not item.get("version"):
                continue
            bounds = _affected_range(cve, item["product"], item["version"])
            if bounds:
                hit = (item, bounds)
                break
        if hit:
            item, bounds = hit
            summary.update(product=item["product"], version=item["version"],
                           range=bounds, status="berdampak")
            findings.append(finding(
                summary["risk"],
                f"{cid}: berdampak pada {item['product']} {item['version']} (rentang {bounds})",
                f"CVSS {summary['score']:.1f} · {summary['summary'][:150]}",
                "A06", "cve-watch",
            ))
        else:
            summary.setdefault("id", cid)
            summary["status"] = "tidak berdampak pada stack ini"
        detail.append(summary)
    return findings, detail


def nvd_product_cves(product: str, version: str, cfg: dict) -> list[dict]:
    """CVE yang BENAR-BENAR berdampak pada versi terpasang.

    NVD menulis banyak CVE sebagai rentang (`*` + versionEndIncluding/Excluding),
    sehingga query versi eksplisit saja melewatkannya (contoh nyata: CVE-2026-91769
    menulis `<= 8.3.35` dan tidak punya CPE `8.3.35`). Karena itu CVE ditarik per
    produk lalu rentangnya dievaluasi sendiri.
    """
    if product not in CPE_MAP or not _vtuple(version):
        return []
    ncfg = cfg["deep_scan"]["nvd"]
    months = max(1, int(ncfg.get("recent_months", 6)))
    windows = max(1, min(6, (months * 30 + 109) // 110))
    if product == "kernel":
        windows = 1  # volume CVE kernel sangat besar; fokus 110 hari terakhir
    items: dict[str, dict] = {}

    # Jalur 1: CPE dengan versi eksplisit — menangkap CVE lama yang sudah
    # dipublikasikan per versi (mis. nginx CVE-2025-23419 untuk 1.24.0).
    proto = "o" if product == "kernel" else "a"
    for vendor, name in CPE_MAP[product]:
        data = nvd_request({"virtualMatchString": f"cpe:2.3:{proto}:{vendor}:{name}:{version}",
                            "resultsPerPage": "50"}, cfg)
        for entry in data.get("vulnerabilities", []):
            summary = _summarize_cve(entry)
            summary["range"] = version
            items.setdefault(summary["id"], summary)

    # Jalur 2: CVE berbentuk rentang dalam jendela waktu terakhir.
    end = datetime.now(timezone.utc)
    for _ in range(windows):
        start = end - timedelta(days=110)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": "200",
        }
        found_any = False
        for vendor, name in CPE_MAP[product]:
            prefix = f":{vendor}:{name}:"
            proto = "o" if product == "kernel" else "a"
            data = nvd_request({**params, "virtualMatchString": f"cpe:2.3:{proto}:{vendor}:{name}"}, cfg)
            for entry in data.get("vulnerabilities", []):
                cve = entry.get("cve", {})
                cid = cve.get("id")
                if not cid or cid in items:
                    continue
                criteria_all = [m.get("criteria") or "" for conf in cve.get("configurations", [])
                                for node in conf.get("nodes", []) for m in node.get("cpeMatch", [])]
                if not any(prefix in c for c in criteria_all):
                    continue
                bounds = _affected_range(cve, product, version)
                if not bounds:
                    continue
                summary = _summarize_cve(entry)
                summary["range"] = bounds
                items[cid] = summary
                found_any = True
        end = start
        if not found_any:
            break
    result = list(items.values())
    max_age = int(ncfg.get("max_age_years", 3))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=365 * max_age)).strftime("%Y-%m-%d")
    for item in result:
        item["historical"] = bool(item["published"]) and item["published"] < cutoff
    result.sort(key=lambda i: i["published"], reverse=True)      # terbaru dulu
    result.sort(key=lambda i: (i["historical"], RISK_ORDER.get(i["risk"], 9)))  # stabil
    return result


# ============================================================ FINGERPRINT
def _first_version(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def detect_local_stack() -> list[dict]:
    """Deteksi versi komponen yang benar-benar terpasang di mesin ini."""
    stack: list[dict] = []
    checks = [
        ("php", ["php", "-v"], r"PHP\s+(\d+\.\d+\.\d+)"),
        ("nodejs", ["node", "-v"], r"v(\d+\.\d+\.\d+)"),
        ("openssl", ["openssl", "version"], r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"),
        ("nginx", ["nginx", "-v"], r"nginx/(\d+\.\d+\.\d+)"),
        ("apache", ["apache2", "-v"], r"Apache/(\d+\.\d+\.\d+)"),
        ("redis", ["redis-server", "--version"], r"v=(\d+\.\d+\.\d+)"),
        ("postgresql", ["postgres", "--version"], r"PostgreSQL\)?\s+(\d+\.\d+(?:\.\d+)?)"),
        ("mysql", ["mysqld", "--version"], r"Ver\s+(\d+\.\d+\.\d+)"),
    ]
    for product, cmd, pattern in checks:
        code, out = sh(cmd, timeout=10)
        if code != 0:
            continue
        version = _first_version(out, pattern)
        if version:
            stack.append({"product": product, "version": version, "source": " ".join(cmd)})

    # kernel (WSL suffix dibuang agar cocok CPE)
    code, out = sh(["uname", "-r"], timeout=5)
    if code == 0:
        raw = out.strip().splitlines()[0] if out.strip() else ""
        match = re.match(r"(\d+\.\d+\.\d+(?:\.\d+)?)", raw)
        if match:
            stack.append({"product": "kernel", "version": match.group(1), "source": f"uname -r ({raw})"})

    # versi paket dpkg (otoritatif, termasuk patch distro)
    dpkg_map = {"php": "php-cli", "nodejs": "nodejs", "openssl": "openssl",
                "nginx": "nginx", "apache": "apache2", "postgresql": "postgresql",
                "mariadb": "mariadb-server", "redis": "redis-server"}
    for product, pkg in dpkg_map.items():
        code, out = sh(["dpkg-query", "-W", "-f=${Version}", pkg], timeout=8)
        version = out.strip() if code == 0 else ""
        if not version:
            continue
        entry = next((s for s in stack if s["product"] == product), None)
        if entry:
            entry["package_version"] = version
        else:
            upstream = re.match(r"(\d+\.\d+(?:\.\d+)?)", version)
            stack.append({"product": product, "version": upstream.group(1) if upstream else version,
                          "source": f"dpkg {pkg}", "package_version": version})
    return stack


def remote_fingerprint(host: str, cfg: dict) -> list[dict]:
    """Ambil versi dari header HTTP (X-Powered-By, Server) — tanpa file lokal."""
    stack: list[dict] = []
    timeout = int(cfg["domain_scan"].get("timeout", 10))
    for scheme in ("https", "http"):
        res = secscan._http_probe_once(host, scheme, timeout, 2)
        if not res["reachable"]:
            continue
        powered = res["headers"].get("x-powered-by", "")
        if "php" in powered.lower():
            version = _first_version(powered, r"PHP/(\d+\.\d+\.\d+)")
            if version and not any(s["product"] == "php" for s in stack):
                stack.append({"product": "php", "version": version,
                              "source": f"X-Powered-By ({scheme})"})
        server = res["headers"].get("server", "")
        if "nginx" in server.lower():
            version = _first_version(server, r"nginx/(\d+\.\d+\.\d+)")
            if version and not any(s["product"] == "nginx" for s in stack):
                stack.append({"product": "nginx", "version": version, "source": f"Server header ({scheme})"})
        if "apache" in server.lower():
            version = _first_version(server, r"Apache/(\d+\.\d+\.\d+)")
            if version and not any(s["product"] == "apache" for s in stack):
                stack.append({"product": "apache", "version": version, "source": f"Server header ({scheme})"})
        if "express" in powered.lower() and not any(s["product"] == "nodejs" for s in stack):
            stack.append({"product": "nodejs", "version": "", "source": f"X-Powered-By Express ({scheme})"})
        break  # https cukup bila berhasil
    return stack


# ================================================================ NUCLEI
def nuclei_available() -> bool:
    code, _ = sh(["nuclei", "-version"], timeout=15)
    return code == 0


def run_nuclei(targets: list[str], cfg: dict) -> list[dict]:
    """Jalankan template cve/exposures/misconfig/owasp (maintained, no DoS/fuzz)."""
    ncfg = cfg["deep_scan"]["nuclei"]
    if not ncfg.get("enabled", True) or not targets or not nuclei_available():
        return []
    out_file = Path(tempfile.mkstemp(suffix=".jsonl", prefix="nuclei_", dir="/tmp")[1])
    cmd = [
        str(ncfg.get("path") or "nuclei"),
        "-jsonl", "-silent", "-nc", "-no-interactsh",
        "-severity", str(ncfg.get("severity", "critical,high")),
        "-rate-limit", str(ncfg.get("rate_limit", 80)),
        "-timeout", str(int(ncfg.get("request_timeout", 8))),
        "-retries", "1",
        "-exclude-tags", "dos,fuzz,brute-force,default-login",
        "-tags", str(ncfg.get("tags", "cve,owasp,exposures,misconfig")),
        "-o", str(out_file),
    ]
    for target in targets:
        cmd += ["-u", target]
    log.info("nuclei mulai: %s target=%s", " ".join(cmd[-2:]), targets)
    started = time.time()
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True, errors="replace", stdin=subprocess.DEVNULL)
        _, stderr = proc.communicate(timeout=int(ncfg.get("timeout", 420)))
        if stderr and "could not" in stderr.lower():
            log.warning("nuclei stderr: %s", stderr[:200])
    except subprocess.TimeoutExpired:
        log.warning("nuclei melewati batas waktu %ss — hasil parsial dipakai", ncfg.get("timeout", 420))
        if proc:
            proc.kill()
            proc.communicate()
    except (OSError, ValueError) as exc:
        log.warning("nuclei gagal dijalankan: %s", exc)
        return []

    findings: list[dict] = []
    try:
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            cve_ids = (info.get("classification") or {}).get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            risk = (info.get("severity") or "medium").lower()
            title = info.get("name", item.get("template-id", "temuan"))
            if cve_ids:
                title = f"{title} ({', '.join(cve_ids[:3])})"
            findings.append(finding(
                risk, title,
                f"{item.get('matched-at') or item.get('host','')} — "
                f"{re.sub(r'\s+', ' ', info.get('description', '') or '')[:180]}",
                "A06", "nuclei",
            ))
    except OSError as exc:
        log.warning("hasil nuclei tidak terbaca: %s", exc)
    finally:
        try:
            out_file.unlink()
        except OSError:
            pass
    log.info("nuclei selesai: %s temuan dalam %ss", len(findings), round(time.time() - started))
    return _dedupe(findings)


# ============================================================ WEB CHECKS
SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref:", "critical", "A01", "Repositori .git terekspos — kode sumber bisa diunduh"),
    ("/.env", "=", "critical", "A05", "File .env terekspos — kredensial/secrets bocor"),
    ("/.env.local", "=", "critical", "A05", "File .env.local terekspos"),
    ("/phpinfo.php", "phpinfo", "high", "A05", "phpinfo terekspos — konfigurasi server bocor"),
    ("/server-status", "Apache Server Status", "high", "A05", "server-status Apache terbuka"),
    ("/actuator/env", "activeProfiles", "critical", "A01", "Spring Actuator env terbuka"),
    ("/.DS_Store", "Bud1", "low", "A05", ".DS_Store terekspos — struktur direktori bocor"),
    ("/composer.json", "require", "medium", "A05", "composer.json terekspos — dependensi terungkap"),
    ("/package.json", "dependencies", "medium", "A05", "package.json terekspos — dependensi terungkap"),
    ("/web.config", "configuration", "medium", "A05", "web.config terekspos"),
    ("/config.php.bak", "<?php", "high", "A05", "Backup konfigurasi PHP terekspos"),
    ("/backup.sql", "INSERT INTO", "critical", "A01", "Dump SQL terekspos"),
    ("/.svn/entries", "svn", "medium", "A01", "Metadata SVN terekspos"),
    ("/uploads/", "Index of /", "medium", "A01", "Directory listing aktif"),
    ("/images/", "Index of /", "low", "A01", "Directory listing pada folder gambar"),
]


def web_checks(host: str, cfg: dict) -> list[dict]:
    """Probe aman: GET saja, tanpa payload perusak, tanpa menulis file."""
    findings: list[dict] = []
    timeout = int(cfg["domain_scan"].get("timeout", 10))
    schemes = ["https", "http"]

    # pilih scheme yang hidup
    alive = []
    for scheme in schemes:
        res = secscan._http_probe_once(host, scheme, timeout, 2)
        if res["reachable"] and res["status"]:
            alive.append((scheme, res))
    if not alive:
        return [finding("info", "Web check dilewati", "HTTP/HTTPS tidak merespons", "A05", "active")]

    scheme, base = alive[0]
    port = 443 if scheme == "https" else 80
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    base_url = f"{scheme}://{host}"

    def get(path: str, timeout_s: int = 8) -> tuple[int | None, str, dict]:
        try:
            if scheme == "https":
                conn = secscan._HttpsV4(host, port, timeout=timeout_s, context=context)
            else:
                conn = secscan._HttpV4(host, port, timeout=timeout_s)
            try:
                conn.request("GET", path, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; OrcaRouterMonitor/1.0)",
                    "Connection": "close", "Accept": "*/*",
                })
                resp = conn.getresponse()
                body = resp.read(40000).decode("utf-8", "replace")
                return resp.status, body, {k.lower(): v for k, v in resp.getheaders()}
            finally:
                conn.close()
        except (OSError, ssl.SSLError, Exception) as exc:  # noqa: BLE001
            log.info("GET %s%s gagal: %s", base_url, path, exc)
            return None, "", {}

    # A01/A05: file & path sensitif (verifikasi signature agar tidak false positive)
    for path, signature, risk, cat, desc in SENSITIVE_PATHS:
        status, body, headers = get(path)
        if status in (200, 403) and signature.lower() in body.lower()[:5000]:
            verified = status == 200
            findings.append(finding(
                risk if verified else "low",
                f"{desc}" + ("" if verified else " (403 — ada tapi terproteksi)"),
                f"{base_url}{path} → HTTP {status}", cat, "verified",
            ))
            if verified and path in ("/.env", "/.git/HEAD"):
                snippet = re.sub(r"\s+", " ", body[:160]).strip()
                findings[-1]["detail"] += f" · bukti: {snippet}"

    # A05: metode HTTP berbahaya
    try:
        conn = (secscan._HttpsV4(host, port, timeout=8, context=context) if scheme == "https"
                else secscan._HttpV4(host, port, timeout=8))
        try:
            conn.request("OPTIONS", "/", headers={"Connection": "close"})
            resp = conn.getresponse()
            allow = resp.getheader("allow") or resp.getheader("Allow") or ""
            resp.read(1000)
        finally:
            conn.close()
        allow_upper = allow.upper()
        if "PUT" in allow_upper or "DELETE" in allow_upper:
            findings.append(finding("medium", "Metode HTTP berbahaya diizinkan",
                                    f"Allow: {allow}", "A05", "verified"))
        if "TRACE" in allow_upper:
            findings.append(finding("low", "TRACE diizinkan (cross-site tracing)",
                                    f"Allow: {allow}", "A05", "verified"))
    except (OSError, ssl.SSLError) as exc:
        log.info("OPTIONS gagal: %s", exc)

    # A03: refleksi canary (indikator XSS, tanpa payload serangan)
    canary = "orcaCanaryF7x21"
    status, body, _ = get(f"/?orca_probe={canary}")
    if status and canary in body:
        findings.append(finding("medium", "Input URL direfleksikan tanpa encoding",
                                "Parameter ?orca_probe= muncul apa adanya di HTML — indikasi XSS",
                                "A03", "verified"))

    # A07: form login lewat HTTP polos
    if scheme == "http":
        for path in ("/login", "/admin", "/wp-login.php"):
            status, body, _ = get(path)
            if status and status < 400 and re.search(r"type=[\"']password", body, re.I):
                findings.append(finding("medium", "Form login dikirim lewat HTTP",
                                        f"http://{host}{path} meminta password tanpa TLS", "A07", "verified"))
                break

    # A02/A05: header keamanan (pakai hasil probe awal)
    headers = base["headers"]
    for name, label, risk in (("strict-transport-security", "HSTS", "medium"),
                              ("content-security-policy", "CSP", "low"),
                              ("x-frame-options", "X-Frame-Options", "low")):
        if name not in headers:
            findings.append(finding(risk, f"Header {label} tidak ada",
                                    f"Tambahkan {name}", "A05", "verified"))
    if scheme == "http":
        findings.append(finding("medium", "Situs dapat diakses lewat HTTP polos",
                                base_url, "A02", "verified"))
    return _dedupe(findings)


# ====================================================== VERIFIKASI EKSPLOITASI
def _tcp(host: str, port: int, timeout: float = 2.5) -> socket.socket | None:
    try:
        return secscan.tcp_connect(host, port, int(timeout))
    except OSError:
        return None


def verify_readonly(host: str, ports: list[int], cfg: dict) -> list[dict]:
    """Pembuktian non-destruktif: hanya perintah baca (PING/INFO/stats/GET)."""
    findings: list[dict] = []
    if not cfg["deep_scan"].get("safe_exploit", True):
        return [finding("info", "Verifikasi eksploitasi dimatikan di config", "", "A05", "config")]

    # --- Redis tanpa autentikasi
    if 6379 in ports:
        sock = _tcp(host, 6379)
        if sock:
            try:
                sock.settimeout(3)
                sock.sendall(b"PING\r\n")
                reply = sock.recv(256).decode("utf-8", "replace")
                if "+PONG" in reply:
                    sock.sendall(b"INFO server\r\nINFO keyspace\r\n")
                    time.sleep(0.4)
                    info = sock.recv(8192).decode("utf-8", "replace")
                    version = _first_version(info, r"redis_version:([\d.]+)") or "?"
                    keys_match = re.search(r"db0:keys=(\d+)", info)
                    keys = keys_match.group(1) if keys_match else "0"
                    findings.append(finding(
                        "critical", "Redis terbuka TANPA autentikasi (terbukti)",
                        f"PING→PONG, versi {version}, key di db0: {keys}. "
                        "Data bisa dibaca/ditulis pihak lain.",
                        "A01", "exploit-verified",
                    ))
            except (OSError, UnicodeError) as exc:
                log.info("redis probe gagal: %s", exc)
            finally:
                sock.close()

    # --- memcached
    if 11211 in ports:
        sock = _tcp(host, 11211)
        if sock:
            try:
                sock.settimeout(3)
                sock.sendall(b"stats\r\n")
                data = sock.recv(4096).decode("utf-8", "replace")
                if "STAT version" in data:
                    findings.append(finding("critical", "Memcached terbuka tanpa autentikasi",
                                            "Perintah stats dijawab tanpa kredensial", "A01", "exploit-verified"))
            except (OSError, UnicodeError):
                pass
            finally:
                sock.close()

    # --- Docker API
    if 2375 in ports:
        status, body, _ = _http_get_ip(host, 2375, "/version", False)
        if status == 200 and "ApiVersion" in body:
            findings.append(finding("critical", "Docker API terbuka TANPA TLS/auth (terbukti)",
                                    "GET /version dijawab — setara akses root ke host", "A01", "exploit-verified"))

    # --- Elasticsearch
    if 9200 in ports:
        status, body, _ = _http_get_ip(host, 9200, "/", False)
        if status == 200 and ("cluster_name" in body or "lucene_version" in body):
            findings.append(finding("high", "Elasticsearch terbuka tanpa autentikasi",
                                    "GET / mengembalikan metadata cluster", "A01", "exploit-verified"))
    return findings


def _http_get_ip(host: str, port: int, path: str, tls: bool,
                 timeout: int = 5) -> tuple[int | None, str, dict]:
    import http.client

    try:
        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"Connection": "close"})
            resp = conn.getresponse()
            return resp.status, resp.read(20000).decode("utf-8", "replace"), \
                {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as exc:
        log.info("GET %s:%s%s gagal: %s", host, port, path, exc)
        return None, "", {}


# ============================================================== ORKESTRASI
def _dedupe(items: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for item in items:
        key = (item["risk"], item["title"][:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def deep_scan(host: str | None, cfg: dict, local: bool = True,
              nuclei_targets: list[str] | None = None) -> tuple[str, str, dict]:
    """host=None → hanya stack lokal; host diisi → tambah web check + CVE remote."""
    cfg = cfg or load_config()
    dcfg = cfg["deep_scan"]
    started = time.time()
    findings: list[dict] = []
    stack: list[dict] = []
    cve_exact: dict[str, list[dict]] = {}

    if local:
        stack.extend(detect_local_stack())
        # bila ada web server lokal, jalankan juga probe OWASP ke 127.0.0.1
        if any(s["product"] in ("apache", "nginx") for s in stack):
            try:
                findings.extend(web_checks("127.0.0.1", cfg))
                findings.extend(verify_readonly("127.0.0.1", [6379, 11211, 2375, 9200], cfg))
            except Exception as exc:  # noqa: BLE001
                log.warning("web check lokal gagal: %s", exc)
    if host:
        stack.extend(remote_fingerprint(host, cfg))
        try:
            findings.extend(web_checks(host, cfg))
        except Exception as exc:  # noqa: BLE001
            log.warning("web check %s gagal: %s", host, exc)
            findings.append(finding("info", "Web check gagal", str(exc)[:150], "A05", "error"))

        ips = secscan.resolve_host(host)
        ports = secscan.scan_ports_socket(host, sorted({6379, 11211, 2375, 9200, 27017}))
        findings.extend(verify_readonly(host, ports, cfg))

    # --- CVE via NVD (exact version + headline terbaru)
    max_products = int(dcfg.get("nvd", {}).get("max_products", 8))
    seen_products: set[str] = set()
    for entry in stack[:max_products]:
        product, version = entry["product"], entry.get("version", "")
        if product in seen_products or not version:
            continue
        seen_products.add(product)
        if product in ("php", "nodejs", "nginx", "apache", "openssl", "kernel", "redis",
                       "postgresql", "mariadb", "mysql", "python", "docker"):
            matched = nvd_product_cves(product, version, cfg)
            if matched:
                cve_exact[product] = matched
                fresh = [i for i in matched if not i.get("historical")]
                if fresh:
                    top = fresh[0]
                    ids = ", ".join(i["id"] for i in fresh[:3])
                    more = f" (+{len(fresh) - 3})" if len(fresh) > 3 else ""
                    findings.append(finding(
                        top["risk"],
                        f"{product} {version}: {len(fresh)} CVE — {ids}{more}",
                        f"Tertinggi CVSS {top['score']:.1f} (rentang {top.get('range', '?')}): "
                        f"{top['summary'][:120]}"
                        + (" · kernel: verifikasi patch WSL/distro, NVD mencatat banyak CVE"
                           if product == "kernel" else ""),
                        "A06", "nvd-range",
                    ))

    # --- watchlist CVE eksplisit (opsional)
    watch_detail: list[dict] = []
    watchlist = cfg["deep_scan"].get("cve_watch") or []
    if watchlist and stack:
        try:
            watch_findings, watch_detail = watch_cves(watchlist, stack, cfg)
            findings.extend(watch_findings)
        except Exception as exc:  # noqa: BLE001
            log.warning("watchlist CVE gagal: %s", exc)

    # --- update keamanan paket (otoritatif untuk paket terinstal, hanya mesin lokal)
    apt_status = "unknown"
    if local:
        try:
            for item in secscan.check_pending_updates():
                findings.append(finding(item["risk"], item["title"], item["detail"], "A06", "apt"))
                title = item["title"].lower()
                if "tidak ada update keamanan" in title:
                    apt_status = "clean"
                elif "update keamanan" in title:
                    apt_status = "pending"
        except Exception as exc:  # noqa: BLE001
            log.warning("cek update gagal: %s", exc)

    # --- nuclei (CVE/OWASP template) — hanya temuan milik scope ini
    targets = nuclei_targets or []
    nuclei_findings = run_nuclei(targets, cfg) if targets else []
    keep = []
    for item in nuclei_findings:
        detail = item.get("detail", "")
        if host:
            if host in detail:
                keep.append(item)
        elif "127.0.0.1" in detail or "localhost" in detail:
            keep.append(item)
    nuclei_findings = keep
    findings.extend(nuclei_findings)

    findings = _dedupe(findings)
    findings.sort(key=lambda f: RISK_ORDER.get(f["risk"], 9))
    real = [f for f in findings if f["risk"] != "info"]
    worst = sorted(real, key=lambda f: RISK_ORDER.get(f["risk"], 9))[0]["risk"] if real else "info"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in real:
        counts[item["risk"]] = counts.get(item["risk"], 0) + 1

    data = {
        "host": host, "local": local, "stack": stack, "findings": findings,
        "cve_exact": cve_exact, "watch_detail": watch_detail, "counts": counts,
        "worst": worst, "nuclei_used": bool(nuclei_findings), "apt_status": apt_status,
        "duration": round(time.time() - started, 1),
    }
    text = format_report(data, cfg)
    save_report("deep_scan", text)
    log.info("Deep scan selesai host=%s worst=%s temuan=%s durasi=%ss",
             host or "local", worst, len(real), data["duration"])
    return text, worst, data


def format_report(data: dict, cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    lines = [
        "🔎 <b>DEEP SCAN — CVE &amp; OWASP TOP 10</b>",
        f"<i>{now_str(cfg.get('timezone_label', 'WIB'))}</i>",
        f"Target: <b>{h(data['host'] or 'server lokal')}</b>",
    ]

    # --- stack
    if data["stack"]:
        lines.append("")
        lines.append("🧬 <b>Komponen terdeteksi</b>")
        for entry in data["stack"]:
            ver = entry.get("version") or "?"
            extra = ""
            if entry.get("package_version") and entry["package_version"] != ver:
                extra = f" <i>(paket {h(entry['package_version'])})</i>"
            lines.append(f"  • {h(entry['product'])} <b>{h(ver)}</b>{extra}")

    # --- CVE exact
    if data["cve_exact"]:
        lines.append("")
        lines.append("🎯 <b>CVE yang berdampak pada versi terpasang</b> <i>(rentang versi NVD dievaluasi)</i>")
        for product, items in data["cve_exact"].items():
            fresh = [i for i in items if not i.get("historical")]
            old = [i for i in items if i.get("historical")]
            for item in fresh[:3]:
                lines.append(f"  {risk_badge(item['risk'])} <b>{h(item['id'])}</b> "
                             f"CVSS {item['score']:.1f} · {h(item['published'])} "
                             f"· <i>{h(item.get('range', ''))}</i>")
                lines.append(f"    <i>{h(item['summary'][:160])}</i>")
            if not fresh:
                lines.append(f"  ✅ {h(product)} {h(items[0].get('published', ''))}: "
                             f"tidak ada CVE baru (≤3 tahun) untuk versi ini")
            if old:
                lines.append(f"  <i>Historis (&gt;3 thn, kemungkinan sudah dipatch / CPE range tidak presisi): "
                             f"{h(', '.join(i['id'] for i in old[:4]))}</i>")

    # --- watchlist eksplisit
    if data.get("watch_detail"):
        lines.append("")
        lines.append("📌 <b>CVE yang dipantau (watchlist)</b>")
        for item in data["watch_detail"][:8]:
            cid = item.get("id", "?")
            status = item.get("status", "")
            if status == "berdampak":
                lines.append(f"  {risk_badge(item['risk'])} <b>{h(cid)}</b> — {h(item['product'])} "
                             f"{h(item['version'])} · rentang {h(item['range'])}")
            elif status == "tidak ditemukan di NVD":
                lines.append(f"  ⚪ {h(cid)} — tidak ditemukan di NVD")
            else:
                lines.append(f"  ✅ {h(cid)} — tidak berdampak (versi di luar rentang)")

    # --- temuan
    real = [f for f in data["findings"] if f["risk"] != "info"]
    info = [f for f in data["findings"] if f["risk"] == "info"]
    lines.append("")
    lines.append(f"🚨 <b>Temuan ({len(real)})</b>")
    if not real:
        lines.append("Tidak ada temuan berisiko ✅")
    shown = 0
    for item in real:
        if shown >= 18:
            lines.append(f"  <i>... +{len(real) - shown} temuan lain (lihat reports/)</i>")
            break
        shown += 1
        cat = OWASP.get(item["owasp"], "")
        lines.append("")
        lines.append(f"{risk_badge(item['risk'])} — <b>{h(item['title'])}</b>")
        lines.append(f"  <i>{h(item['detail'][:220])}</i>")
        meta = []
        if cat:
            meta.append(cat)
        meta.append(f"sumber: {item['source']}")
        lines.append(f"  <code>{h(' · '.join(meta))}</code>")
    if info:
        lines.append("")
        for item in info[:6]:
            lines.append(f"ℹ️ {h(item['title'])}" + (f" — <i>{h(item['detail'][:120])}</i>" if item["detail"] else ""))

    # --- cakupan OWASP
    covered = {item["owasp"] for item in data["findings"] if item["owasp"]}
    lines.append("")
    lines.append("📋 <b>Cakupan OWASP Top 10</b>")
    for code, label in OWASP.items():
        mark = "✅" if code in covered else "·"
        lines.append(f"  {mark} {label}")

    counts = data["counts"]
    lines.append("")
    # rekomendasi singkat berdasarkan komponen yang terdeteksi
    recs: list[str] = []
    products = {entry["product"] for entry in data["stack"]}
    if "php" in products:
        recs.append("PHP: <code>sudo apt update && sudo apt install --only-upgrade php8.3-cli</code>")
    if "nodejs" in products:
        recs.append("Node: perbarui ke rilis LTS terbaru (<code>nvm install --lts</code>)")
    if "openssl" in products:
        recs.append("OpenSSL: <code>sudo apt install --only-upgrade openssl libssl3</code>")
    if data["cve_exact"]:
        recs.append("Cocokkan CVE dengan changelog distro — paket Ubuntu sering sudah backport patch")
    if recs:
        lines.append("🛠 <b>Rekomendasi</b>")
        for rec in recs[:4]:
            lines.append(f"  • {rec}")
        lines.append("")
    # kesimpulan: bedakan CVE berbasis versi vs status patch distro
    apt_status = data.get("apt_status", "unknown")
    if data.get("cve_exact") and apt_status == "clean":
        lines.append("🧩 <b>Kesimpulan</b>: versi dasar komponen memang punya CVE historis, "
                     "tetapi <b>apt melaporkan tidak ada update keamanan tertunda</b> — "
                     "Ubuntu biasanya sudah mem-backport patch. Prioritaskan yang juga "
                     "terdeteksi nuclei atau berstatus terbukti.")
        lines.append("")
    elif apt_status == "pending":
        lines.append("🧩 <b>Kesimpulan</b>: ada update keamanan tertunda — jalankan "
                     "<code>sudo apt update &amp;&amp; sudo apt upgrade</code> sebelum menilai CVE lain.")
        lines.append("")
    # rincian per sumber agar tidak tertukar antara terbukti vs berbasis versi
    by_source: dict[str, int] = {}
    for item in real:
        by_source[item["source"]] = by_source.get(item["source"], 0) + 1
    if by_source:
        labels = {
            "exploit-verified": "terbukti (read-only)",
            "verified": "probe aktif",
            "nvd-exact": "CVE versi (perlu verifikasi)",
            "nvd-range": "CVE berdampak (rentang NVD)",
            "nvd": "CVE versi",
            "nuclei": "template nuclei",
            "apt": "update paket",
            "active": "probe aktif",
            "error": "error",
        }
        parts = [f"{labels.get(k, k)}: {v}" for k, v in sorted(by_source.items(), key=lambda x: -x[1])]
        lines.append("<i>Sumber temuan → " + h(" · ".join(parts)) + "</i>")
    lines.append(f"<b>Ringkasan:</b> 🔴 {counts['critical']} · 🟠 {counts['high']} · "
                 f"🟡 {counts['medium']} · 🔵 {counts['low']}")
    verdict = {"critical": "❌ KRITIS — tindakan segera", "high": "❗ RISIKO TINGGI",
               "medium": "⚠️ PERLU PERHATIAN", "low": "✅ RISIKO RENDAH",
               "info": "✅ BERSIH"}.get(data["worst"], "✅ BERSIH")
    lines.append(f"<b>Status: {verdict}</b> · durasi {data['duration']}s")
    lines.append("<i>Verifikasi eksploitasi bersifat read-only (tanpa payload perusak).</i>")
    return "\n".join(lines)


def _nuclei_targets_for(host: str | None, cfg: dict) -> list[str]:
    """Target nuclei untuk satu scope: lokal (port web) atau satu domain."""
    if host is None:
        ports = [(80, "http"), (8080, "http"), (443, "https"), (8443, "https")]
        return [f"{scheme}://127.0.0.1:{port}" for port, scheme in ports]
    return [f"https://{host}", f"http://{host}"]


def run_cron_deep(cfg: dict | None = None) -> tuple[str, str, dict]:
    """Untuk cron: stack lokal + tiap domain terpantau, nuclei per scope."""
    cfg = cfg or load_config()
    findings_text: list[str] = []
    worst_all = "info"
    domains = cfg["domain_scan"].get("subdomains", [])
    max_hosts = int(cfg["deep_scan"]["nuclei"].get("max_hosts", 3))

    hosts: list[str | None] = [None] + list(domains[:max_hosts])
    for index, host in enumerate(hosts):
        targets = _nuclei_targets_for(host, cfg) if index < max_hosts + 1 else []
        text, worst, _ = deep_scan(host, cfg, local=host is None, nuclei_targets=targets)
        findings_text.append(text)
        if RISK_ORDER.get(worst, 9) < RISK_ORDER.get(worst_all, 9):
            worst_all = worst
    combined = "\n\n" + ("─" * 18) + "\n\n"
    return combined.join(findings_text), worst_all, {}


# ------------------------------------------------------------------ CLI
def main() -> int:
    parser = argparse.ArgumentParser(description="Modul C — CVE + OWASP deep scan")
    parser.add_argument("--local", action="store_true", help="scan stack lokal")
    parser.add_argument("--domain", action="append", default=[], help="domain/subdomain (boleh berulang)")
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--no-nuclei", action="store_true")
    args = parser.parse_args()

    cfg = load_config()
    if args.no_nuclei:
        cfg["deep_scan"]["nuclei"]["enabled"] = False
    if not args.local and not args.domain:
        args.local = True

    try:
        texts = []
        worst_all = "info"
        hosts = ([None] if args.local else []) + list(args.domain)
        for host in hosts:
            text, worst, _ = deep_scan(host, cfg, local=(host is None),
                                       nuclei_targets=_nuclei_targets_for(host, cfg))
            texts.append(text)
            if RISK_ORDER.get(worst, 9) < RISK_ORDER.get(worst_all, 9):
                worst_all = worst
        combined = "\n\n" + ("─" * 18) + "\n\n"
        out = combined.join(texts)
        print(out)
        if args.send:
            TelegramClient(cfg["bot_token"], cfg["chat_id"], logger=log).send(out)
        return 0 if worst_all not in {"critical"} else 2
    except Exception as exc:  # noqa: BLE001
        log.exception("Deep scan gagal: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
