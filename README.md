# PhishGuard AI — Frontend

Frontend HTML, CSS, dan JavaScript murni dengan template Jinja agar mudah diintegrasikan ke Flask.

## Struktur
- `templates/` — halaman Dashboard, Scan URL, Hasil Deteksi, AI Analysis, Evaluasi, Riwayat, Pengaturan.
- `static/css/style.css` — tema Premium Mint Sage dan responsive layout.
- `static/js/app.js` — interaksi sidebar mobile dan submit scan URL.
- `app.py.example` — contoh route Flask; gabungkan dengan backend tim, jangan menimpa kode model.

## Menjalankan
1. Salin folder `templates` dan `static` ke root proyek Flask.
2. Gabungkan route pada `app.py.example` dengan `app.py` utama.
3. Jalankan aplikasi Flask.
4. Buka `http://127.0.0.1:5000/`.

## Kontrak integrasi awal
Frontend mengirim:
```json
{"url": "https://contoh.com"}
```
ke `POST /api/scan`.

Backend diharapkan membalas JSON:
```json
{
  "url": "https://contoh.com",
  "prediction": "phishing",
  "confidence": 96.8,
  "features": {"Panjang URL": 45, "HTTPS": "Tidak"},
  "recommendation": "Hindari tautan ini."
}
```
`prediction` gunakan `phishing` atau `legitimate`. Untuk mengarahkan ke halaman hasil, backend dapat menambahkan `redirect_url: "/result"` atau sesuaikan handler di `static/js/app.js`.

## Catatan
- Angka di Dashboard adalah data ilustratif untuk mockup, ganti dengan data aktual.
- Metrik Evaluasi sengaja kosong sampai hasil pengujian CatBoost tersedia.
- Penjelasan Ollama harus mendukung hasil CatBoost, bukan mengubah label klasifikasi.
- Font DM Sans memakai Google Fonts; jika offline, browser memakai sans-serif fallback.
