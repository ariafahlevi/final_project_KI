# 🛡️ PhishGuard AI (PhisLess)

> **Sistem Deteksi Tautan Phishing Cerdas Berbasis Machine Learning & Penjelasan AI Lokal**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![UI Style](https://img.shields.io/badge/design-Mint%20Sage%20Theme-2e6659.svg)](static/css/style.css)
[![Status](https://img.shields.io/badge/status-Ready%20for%20Integration-success.svg)]()

PhishGuard AI adalah antarmuka web modern dan responsif untuk mendeteksi ancaman tautan (*URL*) phishing. Dibangun menggunakan **Python (Flask)** dan template **Jinja2** dengan arsitektur UI bertema *Mint Sage* yang bersih, cepat, dan siap diintegrasikan dengan model klasifikasi **CatBoost** serta asisten bahasa lokal **Ollama**.

---

## 📑 Daftar Isi

- [Fitur Utama](#-fitur-utama)
- [Struktur Halaman](#-struktur-halaman)
- [Struktur Direktori](#-struktur-direktori)
- [Panduan Instalasi & Menjalankan](#-panduan-instalasi--menjalankan)
  - [Prasyarat](#prasyarat)
  - [Langkah Cepat (Windows 1-Klik)](#langkah-cepat-windows-1-klik)
  - [Langkah Manual (Windows / macOS / Linux)](#langkah-manual-windows--macos--linux)
- [Konfigurasi Lingkungan (.env)](#-konfigurasi-lingkungan-env)
- [Kontrak Integrasi Backend ML & Ollama](#-kontrak-integrasi-backend-ml--ollama)
- [Lisensi](#-lisensi)

---

## 🌟 Fitur Utama

- **🛡️ URL Security Scanner**: Form analisis URL dengan tombol uji cepat instan (*One-Click Sample Test: Pola Phishing, Aman, Host IP*).
- **📊 Real-time Dashboard**: Visualisasi ringkasan statistik, grafik tren 7 hari, dan rasio distribusi keamanan URL.
- **📄 Laporan Hasil Deteksi Dinamis**: Indikator status visual (*Safe* / *Phishing*), skor keyakinan (*confidence level*), tabel ekstraksi fitur URL, dan rekomendasi mitigasi.
- **🧠 AI-Powered Insight**: Halaman interpretasi penjelasan kontekstual berbasis model bahasa lokal (Ollama) untuk membantu pengguna memahami penyebab risiko tautan.
- **◷ Riwayat Pemeriksaan Interaktif**: Log riwayat URL yang diperiksa dalam sesi pengguna dilengkapi opsi bersihkan data.
- **📈 Evaluasi Model & Confusion Matrix**: Halaman metrik performa model (*Precision, Recall, F1-Score*) dengan dukungan switch demo interaktif.
- **📱 Desain Modern & Responsif**: Dibangun dengan CSS murni, tipografi DM Sans, palet warna *Mint Sage*, dan layout adaptif untuk mobile & desktop.

---

## 🖥️ Struktur Halaman

| Rute URL | Nama Halaman | Keterangan |
| :--- | :--- | :--- |
| `/` | **Dashboard** | Ikhtisar aktivitas, grafik deteksi, dan sampel pemeriksaan |
| `/scan` | **Scan URL** | Input form untuk memasukkan dan memeriksa tautan |
| `/result` | **Hasil Deteksi** | Menampilkan hasil klasifikasi, fitur URL, dan rekomendasi |
| `/analysis` | **AI Analysis** | Penjelasan mendalam mengenai temuan indikasi risiko |
| `/history` | **Riwayat** | Daftar URL yang telah dianalisis pada sesi aktif |
| `/evaluation` | **Evaluasi Model** | Metrik performa model CatBoost & Confusion Matrix |
| `/settings` | **Pengaturan** | Preferensi antarmuka & info versi aplikasi |

---

## 📁 Struktur Direktori

```text
PhisLess/
├── static/
│   ├── css/
│   │   ├── style.css             # Desain utama tema Mint Sage (responsive layout)
│   │   └── branding.css          # Styling logo, brand mark, dan tombol uji cepat
│   ├── img/
│   │   └── phishguard-mark.svg   # Ikon & logo resmi PhishGuard AI
│   └── js/
│       └── app.js                # Interaksi sidebar mobile & handler submit scan URL
├── templates/
│   ├── base.html                 # Master layout template Jinja2
│   ├── dashboard.html            # Halaman Dashboard & statistik
│   ├── scanner.html              # Halaman input Scan URL
│   ├── result.html               # Halaman laporan hasil deteksi
│   ├── analysis.html             # Halaman penjelasan AI kontekstual
│   ├── history.html              # Halaman riwayat pemeriksaan sesi
│   ├── evaluation.html           # Halaman metrik evaluasi model
│   └── settings.html             # Halaman pengaturan sistem
├── app.py                        # Entry point server Flask & mock routing
├── requirements.txt              # Daftar dependensi Python
├── run.bat                       # Script launcher 1-klik untuk Windows
├── run.sh                        # Script launcher untuk Linux / macOS
├── .env.example                  # Template variabel lingkungan
├── .gitignore                    # File pengabaian Git (bersih dari cache/temp)
└── README.md                     # Dokumentasi proyek
```

---

## 🚀 Panduan Instalasi & Menjalankan

### Prasyarat
- **Python 3.10** atau versi lebih baru
- Browser modern (Google Chrome, Microsoft Edge, Firefox, Brave, dsb.)

---

### Langkah Cepat (Windows 1-Klik)
Cukup klik dua kali berkas **`run.bat`**. 
Script akan otomatis:
1. Membuka browser ke `http://127.0.0.1:5000`
2. Menjalankan server Flask development

---

### Langkah Manual (Windows / macOS / Linux)

1. **Clone repositori**:
   ```bash
   git clone https://github.com/fathirrizkifadillah/PhisLess.git
   cd PhisLess
   ```

2. **Buat & aktifkan virtual environment (opsional namun disarankan)**:
   - **Windows:**
     ```powershell
     python -m venv .venv
     .venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Jalankan aplikasi**:
   - **Windows / Linux / macOS:**
     ```bash
     python app.py
     ```
   - **Atau Linux / macOS shell script:**
     ```bash
     chmod +x run.sh
     ./run.sh
     ```

5. **Buka di browser**:
   Akses **`http://127.0.0.1:5000/`** di peramban Anda.

---

## ⚙️ Konfigurasi Lingkungan (`.env`)

Salin berkas template `.env.example` menjadi `.env` jika ingin mengubah konfigurasi default:
```bash
cp .env.example .env
```

| Variabel | Default | Deskripsi |
| :--- | :--- | :--- |
| `FLASK_PORT` | `5000` | Port listening server web |
| `FLASK_DEBUG` | `1` | Mode debug (`1` aktif, `0` nonaktif) |
| `SECRET_KEY` | `phishguard-default-dev-key-2026` | Secret key untuk session cookie Flask |

---

## 🔌 Kontrak Integrasi Backend ML & Ollama

Frontend saat ini telah dilengkapi dengan mock response cerdas di fungsi `api_scan()` pada `app.py`. Ketika modul ML kelompok siap disambungkan, hubungkan endpoint `POST /api/scan` dengan format kontrak berikut:

### 1. Request dari Frontend
Dikirim secara JSON ke `POST /api/scan`:
```json
{
  "url": "http://secure-update-login.com"
}
```

### 2. Response yang Diharapkan Frontend
Backend diharapkan mengembalikan respons berstatus HTTP `200 OK` dengan skema JSON:
```json
{
  "url": "http://secure-update-login.com",
  "prediction": "phishing",
  "confidence": 96.8,
  "features": {
    "Panjang URL": "32 karakter",
    "Protokol HTTPS": "Tidak (Tidak Terenkripsi)",
    "Nama Domain": "secure-update-login.com",
    "Kata Kunci Sensitif": "Terdeteksi (login, update, secure)",
    "Karakter Khusus (@ / -)": "Ditemukan (2 tanda hubung)",
    "Format Host IP": "Tidak (Domain Reguler)"
  },
  "recommendation": "Hindari membuka tautan ini dan jangan pernah memasukkan data kredensial.",
  "explanation": "Model mendeteksi anomali pada URL berupa penggunaan kata kunci sensitif yang berisiko tinggi dan ketiadaan enkripsi HTTPS."
}
```

> **Catatan Label:**
> - Nilai `prediction` wajib bernilai `"phishing"` atau `"legitimate"`.
> - `confidence` berupa float (misal `96.8`).
> - `features` berupa key-value dictionary yang akan otomatis dirender di halaman Hasil Deteksi.

---

## 📄 Lisensi

Proyek ini dikembangkan untuk tujuan edukasi dan riset keamanan siber. Bebas digunakan dan dimodifikasi sesuai kebutuhan tim.
