# Instalasi di Server (Ubuntu/Debian)

Panduan memindahkan scanner dari WSL lokal ke server sungguhan. Semua modul memakai
**Python standard library**, jadi tidak ada `pip install`. Yang perlu dipasang hanya
utilitas sistem + nuclei (opsional tapi disarankan).

Uji cepat: Ubuntu 22.04 / 24.04, akses `sudo`, Python ≥ 3.8 (22.04 = 3.10, 24.04 = 3.12).

---

## 0. Ringkasan yang akan dibuat

```
/opt/scanner-bot/              # kode (git clone)
├── config.json                # dibuat dari config.example.json (chmod 600)
├── .env                       # opsional: BOT_TOKEN & ADMIN_CHAT_ID
├── log/ , reports/            # dibuat otomatis
└── ...

/etc/systemd/system/scanner-bot.service   # bot berjalan terus
/etc/cron.d/scanner-bot                   # scan harian 01:00
user sistem: scanner          # pemilik kode, menjalankan bot
```

Dua proses terpisah:
- **bot** (systemd, user `scanner`) — melayani menu Telegram, selalu hidup.
- **cron** (root) — Modul A → B → C tiap 01:00; root supaya bisa membaca `sshd_config`
  dan hitungan update apt. Kalau tidak mau cron sebagai root, lihat bagian 7.

---

## 1. Persiapan sistem

```bash
sudo apt update
sudo apt install -y python3 git curl unzip ca-certificates \
                    nmap openssl iproute2 update-notifier-common

# zona waktu (penting untuk jadwal 01:00)
timedatectl set-timezone Asia/Jakarta
timedatectl | head -3
```

Cek cepat:

```bash
python3 -V                 # ≥ 3.8
command -v nmap openssl ss git
```

Kalau server memakai UTC dan tidak ingin mengubah timezone, jadwal cron nanti digeser
menjadi `0 18 * * *` (lihat bagian 6).

---

## 2. Ambil kode

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin scanner
sudo mkdir -p /opt/scanner-bot
sudo chown scanner:scanner /opt/scanner-bot

sudo -u scanner git clone https://github.com/barlve/monitor-scanner-bot.git /opt/scanner-bot
sudo -u scanner chmod +x /opt/scanner-bot/*.sh
```

Alternatif tanpa GitHub (mis. server tanpa akses repo privat): dari mesin WSL

```bash
rsync -av --exclude log --exclude reports --exclude config.json --exclude .env \
  /mnt/d/Cybersec/orcarouter/hermes/scanner-vuln-deepskv4fl/ user@server:/opt/scanner-bot/
```

---

## 3. Konfigurasi

```bash
cd /opt/scanner-bot
sudo -u scanner cp config.example.json config.json
sudo chown scanner:scanner config.json
sudo chmod 600 config.json
sudo -u scanner nano config.json
```

Isi minimal:

```json
{
  "bot_token": "TOKEN_DARI_BOTFATHER",
  "chat_id": "123456789",
  "timezone_label": "WIB",
  "domain_scan": { "subdomains": ["barlve.com", "www.barlve.com"] }
}
```

Penting untuk server:

| Kunci | Saran untuk server |
|---|---|
| `bot_token` | **pakai bot berbeda** dari yang di WSL. Token sama di dua host = `409 Conflict` (dua instance polling) |
| `chat_id` | numeric, bukan `@username` |
| `monitor.services` | sesuaikan yang benar-benar ada: `nginx`, `mysql`, `postgresql`, `ssh`, `docker` |
| `monitor.exclude_mounts` | hapus entri khas WSL (`/mnt/wsl`, `/mnt/host`); tambahkan mount data yang tidak perlu dipantau |
| `monitor.watch_ports` | port yang wajib listen di server itu |
| `domain_scan.subdomains` | domain yang dipantau harian |
| `deep_scan.nuclei.max_hosts` | default 3; naikkan kalau domain lebih banyak (waktu bertambah ±2–6 menit/domain) |

Token juga bisa lewat `.env` (menang atas `config.json`):

```bash
sudo -u scanner sh -c 'printf "BOT_TOKEN=%s\nADMIN_CHAT_ID=%s\n" "123:ABC" "123456789" > /opt/scanner-bot/.env'
sudo chmod 600 /opt/scanner-bot/.env
```

---

## 4. nuclei (opsional, disarankan untuk Modul C)

Tanpa nuclei, Modul C tetap jalan (CVE dari NVD + probe OWASP), hanya kehilangan
2857 template CVE/exposure.

```bash
cd /tmp
VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep -oP '"tag_name": "v\K[^"]+')
curl -sLO "https://github.com/projectdiscovery/nuclei/releases/download/v${VER}/nuclei_${VER}_linux_amd64.zip"
sudo unzip -o -q "nuclei_${VER}_linux_amd64.zip" -d /usr/local/bin nuclei
sudo chmod +x /usr/local/bin/nuclei

# template (butuh ~300 MB, sekali saja; perbarui berkala)
nuclei -version
sudo -u scanner nuclei -update-templates 2>&1 | tail -3
```

Kalau `uname -m` bukan `x86_64`, ganti `linux_amd64` → `linux_arm64`.

---

## 5. Uji sebelum dijalankan otomatis

Jalankan sebagai user `scanner`, satu per satu. Jangan lanjut kalau ada yang gagal.

```bash
cd /opt/scanner-bot

# 1 Modul A — metrik (tanpa kirim)
sudo -u scanner python3 -m modules.monitor | head -20

# 2 Modul B — port & konfigurasi server
sudo -u scanner python3 -m modules.secscan server --target 127.0.0.1

# 3 Modul B — domain (HTTP & HTTPS terpisah)
sudo -u scanner python3 -m modules.secscan domain barlve.com

# 4 Modul C — CVE (cepat, tanpa nuclei)
sudo -u scanner python3 -m modules.vulnscan --local --no-nuclei

# 5 kirim ke Telegram (paling penting: buktikan token & chat id benar)
sudo -u scanner python3 -m modules.monitor --send
```

Yang normal di server:
- `🌡 Suhu: ⚪ tidak tersedia` pada VPS — tidak ada sensor, bukan error.
- `⚠️ Konfigurasi SSH tidak terbaca` bila dijalankan sebagai user biasa — cron root
  akan melengkapinya.
- `nmap` dipakai otomatis bila terpasang; tanpa nmap tetap jalan lewat TCP connect.

---

## 6. Jalankan bot (systemd) dan cron harian

```bash
# salin unit & cron dari repo
sudo cp /opt/scanner-bot/deploy/scanner-bot.service /etc/systemd/system/
sudo cp /opt/scanner-bot/deploy/scanner-bot.cron /etc/cron.d/scanner-bot
sudo chmod 644 /etc/cron.d/scanner-bot

sudo systemctl daemon-reload
sudo systemctl enable --now scanner-bot
sudo systemctl status scanner-bot --no-pager

# log bot
sudo journalctl -u scanner-bot -n 30 --no-pager
sudo tail -f /opt/scanner-bot/log/bot.log
```

Cron 01:00 (server WIB):

```cron
# /etc/cron.d/scanner-bot — format cron.d memakai kolom user
0 1 * * * root cd /opt/scanner-bot && /usr/bin/python3 cron_scan.py >> log/cron.log 2>&1
```

Server UTC → `0 18 * * *`.

Verifikasi cron terpasang dan akan jalan:

```bash
systemctl status cron --no-pager | head -3
sudo -u scanner python3 /opt/scanner-bot/cron_scan.py --no-send --skip-deep   # simulasi cepat
```

Uji paksa jadwal (tanpa menunggu 01:00):

```bash
sudo -u scanner bash /opt/scanner-bot/run_cron.sh --skip-deep
tail -20 /opt/scanner-bot/log/cron.log
```

---

## 7. Soal user & izin (baca sekali)

| Proses | User | Alasannya |
|---|---|---|
| `scanner-bot.service` | `scanner` | bot menerima input dari internet; jangan root |
| cron harian | `root` | membaca `/etc/ssh/sshd_config` dan menghitung update apt butuh root |

Kalau tidak mau cron sebagai root, dua opsi:

1. Biarkan sebagai `scanner` — laporan akan berisi catatan
   `Konfigurasi SSH tidak terbaca` dan status update `tidak dapat dibaca`.
2. Beri izin baca terbatas:
   ```bash
   sudo usermod -aG adm scanner      # sebagian distro mengizinkan baca log
   sudo chmod 644 /etc/ssh/sshd_config   # turunkan proteksi — tidak disarankan
   ```

Pemindaian hanya untuk aset sendiri. Modul B menyasar `127.0.0.1`; Modul C menyasar
`127.0.0.1` + domain di config. Jangan tambahkan `--target` host orang lain.

---

## 8. Update & perawatan

```bash
cd /opt/scanner-bot
sudo -u scanner git pull
sudo systemctl restart scanner-bot          # bot tidak hot-reload config
sudo -u scanner nuclei -update-templates    # template CVE selalu baru
sudo -u scanner python3 cron_scan.py --no-send --skip-deep   # smoke test
```

Rutin:
- `log/*.log` rotasi otomatis 2 MB × 5; `log/cron.log` tumbuh (tambahkan logrotate bila perlu)
- `reports/` menyimpan setiap laporan; bersihkan berkala:
  `sudo find /opt/scanner-bot/reports -name '*.txt' -mtime +30 -delete`
- `reports/cve_cache.json` cache NVD 24 jam — boleh dihapus kapan saja

---

## 9. Troubleshooting khas server

| Gejala | Penyebab & solusi |
|---|---|
| `409 Conflict` di log bot | dua instance dengan token sama (WSL + server). Hentikan salah satu, atau pakai bot berbeda per host |
| `chat not found` | `chat_id` salah/`@username`; kirim pesan ke bot lalu `/id` |
| Bot hidup tapi tidak membalas | cek `journalctl -u scanner-bot -f`; token salah → `getMe` gagal |
| Cron tidak jalan | `timedatectl` (UTC vs WIB), `systemctl status cron`, lihat `log/cron.log` |
| Semua service "tidak terpasang" | nama unit beda (`mysql` vs `mariadb`, `apache2` vs `httpd`) — sesuaikan `monitor.services` |
| Disk tidak muncul | semua mount terfilter — sesuaikan `monitor.exclude_mounts` |
| `nuclei: command not found` | belum dipasang atau tidak di PATH cron; pakai path absolut di `deep_scan.nuclei.path` |
| Scan lambat / timeout | turunkan `deep_scan.nuclei.rate_limit`, naikkan `timeout`, atau set `max_hosts: 1` |
| NVD 403/429 | rate limit; isi `deep_scan.nvd.api_key` (gratis) atau biarkan cache 24 jam bekerja |
| Bot tidak mengirim laporan cron | cron jalan sebagai user berbeda dan `.env` tidak terbaca — token sudah ada di `config.json`, pastikan `sudo -u root` bisa membacanya (atau isi `.env` dengan path absolut) |

---

## 10. Checklist go-live

```bash
# 1 semua modul lolos uji
cd /opt/scanner-bot && sudo -u scanner python3 cron_scan.py --no-send

# 2 bot aktif & bersih dari error
sudo systemctl is-active scanner-bot
sudo journalctl -u scanner-bot --since "10 min ago" | grep -i error || echo "tanpa error"

# 3 cron terdaftar
grep -v '^#' /etc/cron.d/scanner-bot

# 4 laporan terkirim ke Telegram
sudo tail -5 /opt/scanner-bot/log/cron.log

# 5 izin file
sudo ls -l /opt/scanner-bot/config.json /opt/scanner-bot/.env 2>/dev/null   # harus 600
```

Kalau kelima langkah itu sesuai, sistem siap. Scan harian akan masuk otomatis ke
Telegram setiap 01:00 waktu server.
