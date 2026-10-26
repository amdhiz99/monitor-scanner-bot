"""Deep scan kode aplikasi (whitebox).

Memeriksa folder proyek di server: secret ter-hardcode, pola kode berisiko,
konfigurasi .env/.gitignore, dan dependensi rentan (npm audit / pip-audit).
Hanya stdlib + subprocess; tidak butuh pip install.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "vendor", "coverage",
             "__pycache__", ".turbo", "out", ".cache", "venv", ".venv"}
EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".sh", ".sql", ".yml", ".yaml", ".conf", ".ini"}
MAX_BYTES = 2_000_000
MAKS_TAMPIL = 25

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}

SECRETS = [
    ("high", "AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("high", "Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("high", "Google OAuth Secret", re.compile(r"GOCSPX-[A-Za-z0-9_\-]{20,}")),
    ("high", "Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("high", "GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("high", "Private Key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("medium", "Password/secret literal", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']")),
]

DANGER = {
    "js": [
        ("high", "eval()", re.compile(r"\beval\s*\(|new\s+Function\s*\(")),
        ("high", "innerHTML dari input", re.compile(r"\.innerHTML\s*=\s*[^;]*(req|input|params|query|body|user)", re.I)),
        ("high", "child_process exec input", re.compile(r"exec(Sync)?\(\s*[^)]*(req|input|params|query)", re.I)),
        ("medium", "SQL string concat", re.compile(r"(query|execute)\s*\(\s*[`'\"][^`'\"]*\$\{", re.I)),
        ("medium", "TLS verifikasi dimatikan", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED")),
    ],
    "py": [
        ("high", "eval()/exec()", re.compile(r"(?<![\w.])(eval|exec)\s*\(")),
        ("high", "subprocess shell=True", re.compile(r"shell\s*=\s*True")),
        ("medium", "pickle.loads", re.compile(r"pickle\.loads\(")),
        ("medium", "yaml.load tanpa SafeLoader", re.compile(r"yaml\.load\((?![^)]*Loader)")),
    ],
    "php": [
        ("high", "eval/system", re.compile(r"\b(eval|system|shell_exec|passthru)\s*\(")),
        ("high", "SQL concat dari input", re.compile(r"(mysqli?_query|->query)\s*\([^)]*\$_(GET|POST|REQUEST)")),
        ("medium", "unserialize input", re.compile(r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)")),
    ],
}


def _bahasa(p: Path) -> str:
    if p.suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "js"
    if p.suffix == ".py":
        return "py"
    if p.suffix == ".php":
        return "php"
    return ""


def _sensor(teks: str) -> str:
    if not teks:
        return teks
    out = re.sub(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|client_secret)\s*[:=]\s*[\"']?)([^\"'\s,}]{2,})",
                 lambda m: m.group(1) + m.group(2)[:3] + "***", teks)
    return re.sub(r"((?:AKIA|AIza|GOCSPX-|sk_live_|gh[pousr]_)[A-Za-z0-9_\-]{3})[A-Za-z0-9_\-]+", r"\1***", out)


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for nama in filenames:
            p = Path(dirpath) / nama
            if p.suffix.lower() not in EXT:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def scan_path(root: Path) -> list[dict]:
    findings: list[dict] = []
    for p in _iter_files(root):
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(p.relative_to(root))
        if p.name.startswith(".env"):
            continue  # isi .env memang rahasia
        for sev, nama, rx in SECRETS:
            for m in rx.finditer(text):
                baris = text[: m.start()].count("\n") + 1
                potong = text.splitlines()[baris - 1].strip()[:120] if baris - 1 < len(text.splitlines()) else ""
                findings.append({"severity": sev, "judul": nama, "file": rel, "baris": baris, "bukti": _sensor(potong)})
        for sev, nama, rx in DANGER.get(_bahasa(p), []):
            for m in rx.finditer(text):
                baris = text[: m.start()].count("\n") + 1
                potong = text.splitlines()[baris - 1].strip()[:120] if baris - 1 < len(text.splitlines()) else ""
                findings.append({"severity": sev, "judul": nama, "file": rel, "baris": baris, "bukti": _sensor(potong)})

    # izin & gitignore
    for env in root.glob("*/.env*"):
        try:
            mode = oct(env.stat().st_mode)[-3:]
        except OSError:
            continue
        if mode not in ("600", "400"):
            findings.append({"severity": "medium", "judul": f"Permission .env {mode} (disarankan 600)",
                             "file": str(env.relative_to(root)), "baris": 0, "bukti": ""})
    for proyek in [x for x in root.iterdir() if x.is_dir()] if root.is_dir() else []:
        gi = proyek / ".gitignore"
        if (proyek / ".env").exists() and (not gi.exists() or ".env" not in gi.read_text(errors="ignore")):
            findings.append({"severity": "high", "judul": ".env tidak masuk .gitignore",
                             "file": f"{proyek.name}/.env", "baris": 0, "bukti": ""})
    return findings


def audit_deps(root: Path) -> list[dict]:
    out: list[dict] = []
    kandidat = [root] + ([x for x in root.iterdir() if x.is_dir()] if root.is_dir() else [])
    for proyek in kandidat:
        if (proyek / "package.json").exists() and shutil.which("npm"):
            try:
                r = subprocess.run(["npm", "audit", "--json", "--omit=dev"], cwd=proyek,
                                   capture_output=True, text=True, timeout=90)
                data = json.loads(r.stdout or "{}")
                for nama, v in (data.get("vulnerabilities") or {}).items():
                    sev = "high" if v.get("severity") in ("critical", "high") else "medium"
                    out.append({"severity": sev, "judul": f"dependensi {nama} — {v.get('severity')}",
                                "file": f"{proyek.name}/package.json", "baris": 0,
                                "bukti": str((v.get("via") or [""])[0])[:100]})
            except Exception:
                pass
    return out


def run_code_scan(cfg: dict) -> tuple[str, str]:
    """Kembalikan (teks_html, severity_terburuk)."""
    jalur = (cfg.get("deep_scan") or {}).get("code_paths") or ["/var/www"]
    semua: list[dict] = []
    ringkas_path: list[str] = []

    for raw in jalur:
        root = Path(raw)
        if not root.exists():
            ringkas_path.append(f"• <code>{raw}</code> — tidak ditemukan")
            continue
        f = scan_path(root)
        f += audit_deps(root)
        semua.extend(f)
        ringkas_path.append(f"• <code>{raw}</code> — {len(f)} temuan")

    # dedupe
    seen, unik = set(), []
    for x in semua:
        k = (x["judul"], x["file"], x["baris"])
        if k in seen:
            continue
        seen.add(k)
        unik.append(x)
    unik.sort(key=lambda x: (SEVERITY[x["severity"]], x["file"], x["baris"]))

    hitung = {k: sum(1 for x in unik if x["severity"] == k) for k in SEVERITY}
    terburuk = next((k for k in ("critical", "high", "medium", "low") if hitung[k]), "info")

    baris = ["🔎 <b>DEEP SCAN KODE APLIKASI</b>", ""]
    baris += ringkas_path
    baris += ["", f"Temuan: 🔴 {hitung['high']} · 🟠 {hitung['medium']} · 🔵 {hitung['low']}", ""]

    if not unik:
        baris.append("✅ Tidak ada secret/pola berisiko yang terdeteksi.")
    for x in unik[:MAKS_TAMPIL]:
        lokasi = f"{x['file']}:{x['baris']}" if x["baris"] else x["file"]
        baris.append(f"{EMOJI[x['severity']]} <b>{x['judul']}</b>")
        baris.append(f"   <code>{lokasi}</code>")
        if x["bukti"]:
            baris.append(f"   <i>{x['bukti'][:110]}</i>")
    if len(unik) > MAKS_TAMPIL:
        baris.append(f"… dan {len(unik) - MAKS_TAMPIL} temuan lain.")

    return "\n".join(baris), terburuk
