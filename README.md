# OpenCanary Log Viewer

Aplikasi Go sederhana untuk menampilkan log OpenCanary secara real-time di web interface dengan IP whitelisting.

## Fitur

- ✅ Real-time log streaming menggunakan Server-Sent Events (SSE)
- ✅ IP Whitelisting untuk keamanan
- ✅ **Top 10 IP Penyerang** - Statistik IP yang paling banyak menyerang
- ✅ **Top 10 Target Diserang** - Host yang paling sering diserang
- ✅ Auto-refresh statistik setiap 5 detik
- ✅ Format JSON yang cantik dan mudah dibaca
- ✅ Interface web yang responsif dengan tema dark
- ✅ Auto-scroll untuk log terbaru
- ✅ Batasan maksimal 100 log entry untuk performa optimal

## Persyaratan

- Go 1.16 atau lebih baru
- Akses ke file `/var/tmp/opencanary.log`
- Command `tail` dan `jq` (opsional, sudah di-handle oleh Go)

## Instalasi

1. **Simpan file `opencanary-viewer.go`**

2. **Edit daftar IP yang diizinkan**
   
   Buka file dan edit bagian `allowedIPs`:
   ```go
   var allowedIPs = []string{
       "127.0.0.1",
       "192.168.1.100", // Ganti dengan IP Anda
       "10.0.0.5",      // Tambahkan IP lain
   }
   ```

3. **Build aplikasi**
   ```bash
   go build -o opencanary-viewer opencanary-viewer.go
   ```

4. **Jalankan aplikasi**
   ```bash
   # Pastikan Anda punya akses ke log file
   sudo ./opencanary-viewer
   
   # Atau jika file log bisa dibaca tanpa sudo:
   ./opencanary-viewer
   ```

## Penggunaan

1. Jalankan aplikasi
2. Buka browser dari IP yang diizinkan
3. Akses: `http://server-ip:8080`
4. Log akan muncul secara real-time
5. Statistik Top 10 IP Penyerang dan Top 10 Target akan diupdate otomatis setiap 5 detik

## Fitur Statistik

Aplikasi secara otomatis melacak dan menampilkan:
- **Top 10 IP Penyerang**: IP address yang paling sering melakukan serangan
- **Top 10 Target Diserang**: Host/service yang paling sering menjadi target

Statistik dihitung dari awal aplikasi dijalankan dan akan di-reset ketika aplikasi di-restart. Data diambil dari field `src_host` dan `dst_host` di log JSON OpenCanary.

## Konfigurasi

### Mengubah Port

Edit bagian ini di `main()`:
```go
port := ":8080"  // Ganti ke port yang diinginkan
```

### Mengubah Path Log File

Edit bagian ini di `tailLog()`:
```go
cmd := exec.Command("tail", "-f", "/var/tmp/opencanary.log")
// Ganti dengan path log file Anda
```

### Menambahkan IP Range

Untuk mengizinkan seluruh subnet, Anda bisa modifikasi fungsi `ipWhitelistMiddleware`:
```go
// Contoh: izinkan 192.168.1.0/24
if strings.HasPrefix(ip, "192.168.1.") {
    allowed = true
}
```

## Menjalankan sebagai Service (Systemd)

Buat file `/etc/systemd/system/opencanary-viewer.service`:

```ini
[Unit]
Description=OpenCanary Log Viewer
After=network.target

[Service]
Type=simple
User=root
ExecStart=/path/to/opencanary-viewer
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Kemudian:
```bash
sudo systemctl daemon-reload
sudo systemctl enable opencanary-viewer
sudo systemctl start opencanary-viewer
sudo systemctl status opencanary-viewer
```

## Keamanan

- ✅ IP Whitelisting aktif secara default
- ⚠️  Gunakan HTTPS di production (tambahkan reverse proxy seperti Nginx)
- ⚠️  Pastikan file log hanya bisa dibaca oleh user yang tepat
- ⚠️  Jangan expose ke internet publik tanpa keamanan tambahan

## Troubleshooting

### Error: Permission Denied
```bash
# Berikan akses ke log file
sudo chmod 644 /var/tmp/opencanary.log

# Atau jalankan dengan sudo
sudo ./opencanary-viewer
```

### Error: Address Already in Use
Port 8080 sudah digunakan. Ganti ke port lain atau hentikan aplikasi yang menggunakan port tersebut:
```bash
# Cek process yang menggunakan port 8080
sudo lsof -i :8080

# Atau ganti port di kode
```

### Log Tidak Muncul
- Pastikan file `/var/tmp/opencanary.log` ada dan bisa dibaca
- Cek apakah OpenCanary sedang berjalan
- Lihat log error di terminal tempat aplikasi dijalankan

## Lisensi

MIT License - Bebas digunakan dan dimodifikasi
