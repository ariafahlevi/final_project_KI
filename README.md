# 🛡️ PhisGuard: Sistem Deteksi Phishing URL & Email

> **Aplikasi web keamanan informasi untuk mendeteksi ancaman tautan dan pesan email phishing.**  
> *Final Project Mata Kuliah Keamanan Informasi — Program Studi Informatika, Universitas Siliwangi*

---

## 🌟 Fitur Utama

- **Pemeriksaan Tautan (URL)**: Memindai struktur alamat tautan untuk mengenali pola domain tiruan dan situs berbahaya.
- **Pemeriksaan Pesan (Email)**: Menganalisis isi pesan email untuk mengidentifikasi indikasi rekayasa sosial atau penipuan.
- **Verifikasi Berlapis**: Menghubungkan deteksi pola otomatis dengan verifikasi konteks berbasis AI lokal.
- **Laporan Keamanan Interaktif**: Menampilkan tingkat keyakinan, indikator risiko yang ditemukan, dan saran tindakan bagi pengguna.
- **Evaluasi & Riwayat**: Menampilkan metrik akurasi pengujian sistem serta riwayat pemeriksaan terkini.

---

## 🖥️ Halaman Aplikasi

| Halaman | Rute | Deskripsi |
| :--- | :--- | :--- |
| **Dashboard** | `/` | Ringkasan statistik aktivitas dan ikhtisar deteksi. |
| **Scan Ancaman** | `/scan` | Formulir pemeriksaan URL atau isi pesan email. |
| **Hasil Pemeriksaan** | `/result` | Laporan status keamanan, indikator risiko, dan rekomendasi. |
| **Penjelasan Analisis** | `/analysis` | Penjelasan mendalam mengenai temuan indikasi ancaman. |
| **Riwayat** | `/history` | Daftar riwayat pemeriksaan yang telah dilakukan. |
| **Evaluasi Akurasi** | `/evaluation` | Hasil pengujian akurasi sistem (Confusion Matrix & Metrik). |
| **Pengaturan** | `/settings` | Pengaturan tampilan dan informasi sistem. |

---

## 📁 Struktur Direktori

```text
PhisLess/
├── models/                       # Model deteksi URL dan Email
│   ├── email/
│   └── url/
├── static/                       # Aset CSS, JavaScript, dan Ikon
│   ├── css/
│   ├── img/
│   └── js/
├── templates/                    # Template tampilan antarmuka (HTML)
│   ├── base.html
│   ├── dashboard.html
│   ├── scanner.html
│   ├── result.html
│   ├── analysis.html
│   ├── history.html
│   ├── evaluation.html
│   └── settings.html
├── app.py                        # Program server Flask utama
├── ml_engine.py                  # Modul deteksi pola dan verifikasi keamanan
├── requirements.txt              # Daftar dependensi Python
├── .gitignore
└── README.md
```

---

## 🚀 Cara Menjalankan

1. **Install dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Jalankan aplikasi**:
   ```bash
   python app.py
   ```

3. **Buka di browser**:
   Akses alamat: **`http://127.0.0.1:5000/`**

---

## 📄 Lisensi
Dikembangkan untuk keperluan edukasi dan riset keamanan informasi.
