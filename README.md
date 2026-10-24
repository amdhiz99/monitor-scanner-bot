# Sistem Monitoring & Security Scan + Bot Telegram

Dua modul, satu bot, satu cron:

- **Modul A — Monitoring Server** (`modules/monitor.py`): uptime, CPU, RAM/swap, disk per
  partisi, load average, status service, koneksi aktif & port penting, suhu.
- **Modul B — Security Scan** (`modules/secscan.py`): port terbuka + konfigurasi rawan +
  update keamanan (server), serta HTTP/HTTPS terpisah + SSL/TLS (domain/subdomain).
- **Bot Telegram** (`bot.py`): menu inline keyboard & reply keyboard (1 Monitoring,
  2 Scan Server, 3 Scan Domain).
- **Cron** (`cron_scan.py` + `run_cron.sh`): setiap **01:00 WIB** Modul A lalu Modul B
  dijalankan berurutan, hasil dikirim otomatis ke Telegram.

Seluruh kode memakai **Python standard library** — tidak perlu `pip install`, termasuk
untuk bot (pakai `urllib`, bukan `python-telegram-bot`).

---

## 1. Struktur proyek

```
scanner-vuln-deepskv4fl/
├── bot.py                 # bot Telegram (menu interaktif, long polling)
├── cron_scan.py           # runner: Modul A → Modul B → kirim Telegram
├── run_cron.sh            # wrapper cron (muat .env, tulis log/cron.log)
├── start_bot.sh           # jalankan bot di background (pid file)
├── stop_bot.sh            # hentikan bot (hindari 409 Conflict)
├── config.json            # konfigurasi aktif (token, chat id, threshold, domain)
├── config.example.json    # template konfigurasi
├── requirements.txt       # catatan dependency (kosong: stdlib only)
├── core/
│   ├── settings.py        # loader config + default + override env
│   ├── tg.py              # klien Telegram Bot API (send, chunk, long poll)
│   └── utils.py           # logging rotasi, format, badge risiko
├── modules/
│   ├── monitor.py         # MODUL A
│   ├── secscan.py         # MODUL B (server & domain)
│   └── vulnscan.py        # MODUL C (CVE + OWASP + verifikasi read-only)
├── log/                   # monitor.log, secscan.log, bot.log, cron.log
└── reports/               # arsip tiap laporan (txt, timestamp)
```

---

## 2. Dependency

| Kebutuhan | Status | Catatan |
|---|---|---|
| Python ≥ 3.8 | wajib | diuji pada 3.14 (`/usr/bin/python3`) |
| `nmap` | disarankan | tanpa nmap otomatis pakai TCP connect Python (lebih lambat, tetap jalan) |
| `openssl` | disarankan | detail sertifikat saat verifikasi gagal + probe TLS 1.0/1.1 & cipher lemah |
| `iproute2` (`ss`) | disarankan | daftar port/koneksi; fallback ke `/proc/net/tcp` |
| `systemd` | opsional | status service; tanpa systemd dibaca dari proses (`pgrep`) |
| `update-notifier-common` | opsional | hitungan update keamanan via `apt-check` |

Install di Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 nmap openssl iproute2 update-notifier-common
```

Tidak ada paket pip yang dibutuhkan. Kalau tetap ingin venv:

```bash
python3 -m venv .venv && . .venv/bin/activate   # lalu jalankan dengan python
```

> Catatan WSL: `nmap` bisa dipasang tanpa sudo lewat binary statis, tapi cara termudah
> tetap `sudo apt install nmap`. Tanpa nmap, Modul B memakai pemindai socket bawaan.

---

## 3. Setup dari nol

### 3.1 Siapkan bot Telegram

1. Chat `@BotFather` → `/newbot` → simpan **token**.
2. Kirim satu pesan apa pun ke bot Anda, lalu buka:
   `https://api.telegram.org/bot<TOKEN>/getUpdates` → ambil `chat.id` (numerik).
   Alternatif: jalankan bot lalu kirim `/id`.
3. **chat_id harus numerik**, bukan `@username` (Telegram menolak username untuk chat pribadi).

### 3.2 Konfigurasi

```bash
cp config.example.json config.json
nano config.json
```

Isi minimal:

```json
{
  "bot_token": "123456:ABC...",
  "chat_id": "6162635546",
  "domain_scan": { "subdomains": ["barlve.com", "www.barlve.com"] }
}
```

Bisa juga lewat environment (menang atas `config.json`) — berguna untuk cron/kontainer:

```bash
export BOT_TOKEN="123456:ABC..."
export ADMIN_CHAT_ID="6162635546"
```

Threshold yang bisa diatur di `monitor`:

| Kunci | Arti |
|---|---|
| `cpu.warn` / `cpu.crit` | persen CPU (default 80/95) |
| `ram.warn` / `ram.crit` | persen RAM terpakai (80/95) |
| `disk.warn` / `disk.crit` | persen disk per partisi (80/90) |
| `load_per_core.warn` / `.crit` | load avg ÷ jumlah core (1.0/2.0) |
| `temperature.warn` / `.crit` | °C (70/85) |
| `services` | service yang dipantau |
| `services_critical` | service yang mati = ❌ (lainnya ⚠️) |
| `watch_ports` | port yang harus listen |

### 3.3 Testing modul (tanpa bot)

```bash
# Modul A: cetak ke layar
/usr/bin/python3 -m modules.monitor

# Modul A: kirim ke Telegram
/usr/bin/python3 -m modules.monitor --send

# Modul B server
/usr/bin/python3 -m modules.secscan server --target 127.0.0.1

# Modul B domain (HTTP & HTTPS terpisah)
/usr/bin/python3 -m modules.secscan domain barlve.com
/usr/bin/python3 -m modules.secscan domain barlve.com www.barlve.com --send

# Simulasi lengkap cron (tanpa kirim)
/usr/bin/python3 cron_scan.py --no-send
```

### 3.4 Jalankan bot

```bash
chmod +x start_bot.sh stop_bot.sh run_cron.sh bot.py cron_scan.py
./start_bot.sh          # background + log/bot.pid
tail -f log/bot.log     # pantau
./stop_bot.sh           # hentikan
```

Buka Telegram → kirim `/start` → menu tombol muncul.

> Hanya satu instance bot boleh polling dengan token yang sama. Kalau muncul
> `409 Conflict` di log, jalankan `./stop_bot.sh` dulu.

### 3.5 Cron 01:00 WIB

Sistem ini berjalan di zona waktu `Asia/Jakarta`, jadi jam cron = jam WIB:

```cron
# Modul A + Modul B setiap 01:00 WIB
0 1 * * * cd /mnt/d/Cybersec/orcarouter/hermes/scanner-vuln-deepskv4fl && /usr/bin/python3 cron_scan.py >> log/cron.log 2>&1
```

Kalau server memakai **UTC** (cek `timedatectl`), 01:00 WIB = 18:00 UTC hari sebelumnya:

```cron
0 18 * * * ...        # 01:00 WIB pada mesin UTC
```

Pasang:

```bash
( crontab -l 2>/dev/null; echo '0 1 * * * cd /path/ke/proyek && /usr/bin/python3 cron_scan.py >> log/cron.log 2>&1' ) | crontab -
crontab -l      # verifikasi
```

Pakai wrapper bila ingin `.env` ikut dibaca:

```cron
0 1 * * * cd /path/ke/proyek && ./run_cron.sh >> log/cron.log 2>&1
```

Opsi runner: `--skip-domains`, `--skip-monitor`, `--no-send`.

> Cron memakai `/usr/bin/python3` (python sistem). Jangan pakai `python3` dari venv
> Hermes/agen — path-nya bisa berbeda dan hilang setelah restart.

---

## 4. Menu bot

| Tombol | Aksi |
|---|---|
| 1️⃣ Monitoring Server | Modul A, hasil langsung dikirim |
| 2️⃣ Scan Server | Modul B: port, port berisiko, SSH config, update keamanan |
| 3️⃣ Scan Domain | bot minta nama domain → HTTP & HTTPS diperiksa terpisah |
| 4️⃣ Deep Scan | CVE (NVD + nuclei) & OWASP Top 10 + verifikasi eksploitasi read-only |
| 📋 Domain terpantau | daftar `domain_scan.subdomains` |
| ℹ️ Status | status bot, config, jadwal |

Perintah teks: `/start`, `/menu`, `/monitor`, `/scan_server`, `/scan_domain`,
`/scan contoh.com`, `/deep`, `/cve contoh.com`, `/domains`, `/status`, `/id`, `/cancel`.

Saat memilih **3️⃣ Scan Domain**, bot menunggu input (10 menit):

```
barlve.com
barlve.com, www.barlve.com
```
(maksimal 5 domain per permintaan)

---

## 5. Modul C — Deep Scan: CVE & OWASP

Menjawab pertanyaan "apakah versi PHP/Node/OpenSSL saya kena CVE terbaru?" dengan
data nyata, bukan tebakan.

**Cakupan: server DAN domain.** Satu laporan dipisah per target:

| Target | Yang diperiksa di deep scan |
|---|---|
| Server lokal | fingerprint versi terpasang, CVE NVD vs versi, update `apt`, probe file sensitif & header ke `127.0.0.1`, verifikasi service terbuka (Redis/Memcached/Docker/ES), nuclei ke port web lokal |
| Tiap domain di `domain_scan.subdomains` | fingerprint dari header (`Server`/`X-Powered-By`), CVE NVD untuk versi itu, OWASP web checks, nuclei ke `https://` & `http://` domain tersebut |

nuclei dijalankan **per scope** dan hasilnya difilter per host, jadi temuan
`127.0.0.1` tidak pernah muncul di laporan domain (dan sebaliknya). Jumlah domain
yang ikut dipindai dibatasi `deep_scan.nuclei.max_hosts` (default 3).

| Perintah | Scope |
|---|---|
| tombol 4️⃣ / `/deep` | server lokal + semua domain di config (maks `max_hosts`) |
| `/cve barlve.com` | domain itu saja (`local=False`) |
| `python3 -m modules.vulnscan --local` | server lokal saja |
| `python3 -m modules.vulnscan --domain barlve.com` | domain saja |
| `--local --domain x` | keduanya, dua laporan terpisah |

Empat lapis per target:

**1. Fingerprint** — versi yang benar-benar terpasang: PHP, Node, nginx, Apache,
OpenSSL, kernel, Redis, PostgreSQL/MySQL (dari perintah versi + `dpkg-query`),
plus header `Server`/`X-Powered-By` untuk target remote.

**2. CVE — empat sumber independen**

| Sumber | Sifat | Contoh keluaran |
|---|---|---|
| NVD per produk + evaluasi rentang versi | CVE yang benar-benar berdampak | `php 8.3.35 → CVE-2026-109618 (9.8), rentang >=8.3.0 <8.3.36` |
| `apt` update keamanan tertunda | otoritatif untuk paket terinstal | `26 paket dapat di-upgrade` |
| `nuclei` template `cve,owasp,exposures,misconfig` | exploit check aktif (maintained) | `Apache 2.4.58 path traversal` |
| `cve_watch` (opsional) | CVE yang Anda pin manual | `CVE-2026-91769 → tidak berdampak` |

**Kenapa bukan sekadar cocok versi:** NVD sering menulis CVE sebagai rentang
(`cpe:2.3:a:php:php:*` + `versionEndExcluding`). Pencocokan versi eksplisit saja
melewatkan CVE seperti itu. Skrip menarik semua CVE produk dalam jendela waktu
(`recent_months`, default 12 bulan, dipotong per 110 hari karena batas NVD) lalu
mengevaluasi `versionStartIncluding/Excluding` dan `versionEndIncluding/Excluding`
terhadap versi terpasang. Contoh hasil nyata: PHP 8.3.34 → 10 CVE berdampak,
8.3.35 → 2, 8.3.36 → 0.

Tidak perlu mengirim daftar CVE. Kalau ingin memantau CVE tertentu (mis. dari
advisori vendor yang belum masuk NVD), isi `deep_scan.cve_watch` dan hasilnya
dinilai terhadap stack Anda.

CVE yang lebih tua dari 3 tahun dipisah sebagai **historis** (kemungkinan sudah
dipatch distro atau CPE range NVD tidak presisi) agar tidak menakut-nakuti.

**3. OWASP Top 10 (A01–A10)** — probe aman:
- A01: `/.git/HEAD`, `/.env`, `/backup.sql`, `/.svn`, directory listing
- A02: HTTP tanpa TLS, HSTS, versi/cipher TLS (dari Modul B)
- A03: refleksi canary `?orca_probe=` (indikator XSS, tanpa payload)
- A05: `/phpinfo.php`, `/server-status`, `/actuator/env`, metode HTTP
  (`OPTIONS`/`TRACE`), header keamanan
- A06: semua temuan CVE + update paket
- A07: form login yang dikirim lewat HTTP polos

**4. Verifikasi eksploitasi — read-only, tanpa payload perusak**
- Redis `6379`: `PING` → bila `+PONG`, bukti akses tanpa autentikasi (+ versi, DBSIZE)
- Memcached `11211`: `stats`
- Docker API `2375`: `GET /version`
- Elasticsearch `9200`: `GET /`

Tidak ada: brute force password, RCE, upload shell, DoS, SQLi weaponized.
Template `dos`, `fuzz`, `brute-force`, `default-login` sengaja dikecualikan.

### Konfigurasi (`deep_scan`)

```json
"deep_scan": {
  "enabled": true,
  "nvd": {"enabled": true, "api_key": "", "max_products": 8,
          "recent_months": 6, "recent_windows": 2, "max_age_years": 3,
          "cache_hours": 24},
  "nuclei": {"enabled": true, "severity": "critical,high,medium",
             "tags": "cve,owasp,exposures,misconfig", "rate_limit": 80,
             "timeout": 420},
  "safe_exploit": true,
  "cron_deep": true,
  "cve_watch": ["CVE-2026-109618"]
}
```

- Tanpa `nvd.api_key` NVD dibatasi 5 permintaan/30 detik (skrip otomatis jeda +
  cache 24 jam di `reports/cve_cache.json`). API key gratis dari
  https://nvd.nist.gov/developers/request-an-api-key membuatnya jauh lebih cepat.
- `safe_exploit: false` → matikan seluruh verifikasi eksploitasi.
- `nuclei.timeout` membatasi durasi; hasil parsial tetap dipakai bila timeout.

### Menjalankan

```bash
python3 -m modules.vulnscan --local                     # stack mesin ini + CVE
python3 -m modules.vulnscan --domain barlve.com         # web + CVE + nuclei
python3 -m modules.vulnscan --local --domain barlve.com --send
python3 -m modules.vulnscan --local --no-nuclei         # cepat, tanpa nuclei
python3 cron_scan.py --skip-deep                        # cron tanpa Modul C
```

Cron 01:00 menjalankan Modul C otomatis (setelah A dan B) bila
`deep_scan.enabled` dan `cron_deep` bernilai true. Estimasi: 60–180 detik
dengan cache NVD hangat.

## 6. Isi laporan


**Modul A** — uptime, CPU (+jumlah core), RAM/swap, disk per partisi, load 1/5/15,
daftar service (✅ aktif / ⚠️ mati non-kritis / ❌ mati kritis), koneksi aktif, port
listen, port yang diharapkan, suhu, plus baris status akhir
`✅ SEMUA NORMAL` / `⚠️ PERLU PERHATIAN` / `❌ KRITIS`.

**Modul B server** — port terbuka (nmap atau socket), port yang listen di semua
interface, port berisiko (Redis 6379, Mongo 27017, Docker API 2375, RDP 3389 → critical;
Postgres/MySQL/Elasticsearch → high), temuan `sshd_config` (root login, password auth,
empty password, X11), dan update keamanan tertunda.

**Modul B domain** — blok HTTP dan HTTPS **terpisah**:

```
✅ HTTP: status 301 → 200 · 206 ms
  Judul: Barlve
  Redirect: 301 → https://barlve.com/ | 200
✅ HTTPS: status 200 · 123 ms
⚖️ HTTP dialihkan ke HTTPS (301 → 200)
🔒 SSL/TLS: sisa 37 hari, TLSv1.3, TLS_AES_256_GCM_SHA384
```

Temuan diberi badge 🔴 critical / 🟠 high / 🟡 medium / 🔵 low, dengan ringkasan
hitungan per tingkat. Pemeriksaan mencakup: DNS resolve, HTTP vs HTTPS, rantai
redirect, sertifikat (kedaluwarsa/segera habis/tidak valid), TLS 1.0/1.1, cipher lemah
(3DES/RC4/NULL via openssl), header keamanan (HSTS/CSP/X-Frame-Options/
X-Content-Type-Options/Referrer-Policy), error 5xx, dan versi server terekspos.

Semua laporan disimpan juga ke `reports/*.txt`; log audit di `log/*.log` (rotasi 2 MB,
5 arsip).

---

## 7. Ketahanan error

- Domain tidak resolve, port tertutup, TLS gagal, timeout, `nmap` tidak ada,
  `sshd_config` tak terbaca, apt tanpa root → ditangani dan dilaporkan sebagai temuan
  atau catatan; proses tidak crash.
- Satu tahap cron gagal tidak menghentikan tahap lain; kegagalan dikirim ke Telegram.
- Bot: satu update bermasalah tidak mematikan polling; error 409 dilaporkan dengan
  saran hentikan instance lama; `sendMessage` retry 3× dan turun ke plain text bila
  HTML ditolak.
- Pesan panjang dipecah otomatis (< 3800 karakter/pesan).

## 8. Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `chat not found` | `chat_id` masih `@username` atau belum kirim pesan ke bot |
| `409 Conflict` | ada instance bot lain; `./stop_bot.sh` lalu `./start_bot.sh` |
| Bot diam | cek `tail log/bot.log`; token salah → `getMe` gagal |
| Cron tidak jalan | `timedatectl` (zona waktu!), `tail log/cron.log`, pastikan `cron` aktif: `systemctl status cron` |
| Semua service "tidak terpasang" | nama unit beda (mis. `mariadb`, `apache2`) — sesuaikan `monitor.services` |
| Disk kosong | semua mount terfilter `exclude_mounts` (mis. WSL `/mnt/c`) — sesuaikan daftar |
| Metrik suhu kosong | WSL/VM tidak mengekspos sensor — normal (⚪) |
| Scan port lambat | pasang `nmap`, atau perkecil `socket_fallback_ports` |

---

## 9. Catatan izin

Pemindaian hanya untuk server dan domain milik sendiri. Port scan dan pemeriksaan
konfigurasi dijalankan ke `127.0.0.1` secara default; untuk host lain ubah
`--target` dan pastikan Anda berhak memindainya. Beberapa pemeriksaan server
(`sshd_config`, hitungan update apt) butuh akses baca root — tanpa itu dilaporkan
sebagai catatan, bukan error.
