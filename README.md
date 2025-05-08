# Nginx Gateway Manager

Aplikasi manajemen Nginx Gateway untuk mengelola multiple domain dan service pada satu server VPS.

## Fitur

- Manajemen domain dan subdomain
- Konfigurasi reverse proxy untuk multiple service
- Interface web untuk pendaftaran service baru
- Binding domain/subdomain dengan service
- Manajemen konfigurasi Nginx secara dinamis

## Struktur Proyek

```
/nginx-gateway
├── backend/           # Backend service (Golang)
│   ├── api/          # API handlers
│   ├── config/       # Konfigurasi aplikasi
│   ├── models/       # Data models
│   └── services/     # Business logic
├── frontend/         # Frontend web interface
│   ├── css/         # Stylesheet
│   ├── js/          # JavaScript files
│   └── index.html   # Halaman utama
├── nginx/           # Konfigurasi Nginx
│   ├── conf.d/      # Konfigurasi domain
│   └── templates/   # Template konfigurasi
└── docker/          # Docker configuration
```

## Teknologi

- Backend: Go (Golang)
- Frontend: HTML, JavaScript, CSS
- Server: Nginx
- Database: SQLite

## Penggunaan

1. Setup Nginx configuration
2. Jalankan backend service
3. Akses web interface untuk manajemen domain dan service

## Development

```bash
# Menjalankan backend service
cd backend
go run main.go

# Mengakses web interface
http://localhost:8081
```