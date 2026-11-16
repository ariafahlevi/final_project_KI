# 🛡️ PhisGuard: Sistem Deteksi Phishing URL & Email Hybrid

> **Aplikasi pertahanan siber berlapis (Defensive AI) berbasis Supervised Machine Learning dan Local LLM (Qwen 2.5 7B).**  
> *Final Project Mata Kuliah Keamanan Informasi (KP70065004) — Program Studi Informatika, Fakultas Teknik, Universitas Siliwangi (Semester Ganjil 2026/2027).*  
> **Dosen Pengampu**: Muhammad Sidik Asyaky, S.T., M.T.

---

## 🌟 Fitur Utama

- **Pemeriksaan Tautan (URL - Tier 1)**: Memindai struktur alamat tautan menggunakan model **XGBoost Classifier** terlatih pada 100.871 sampel (18 fitur leksikal & struktural).
- **Pemeriksaan Pesan (Email Dwibahasa - Tier 1)**: Menganalisis naskah email menggunakan model **Calibrated Linear SVM (35.000 TF-IDF N-Gram)** dwibahasa (Indonesia & Inggris).
- **Pemeriksa AI Kontekstual (Tier 2 - Qwen 2.5 7B)**: Mengevaluasi taktik rekayasa sosial (*urgensi, peniruan entitas, pencurian kredensial, dugaan motif*) secara independen (*Blind Assessment*).
- **Matriks Rekonsiliasi Bab 10**: Menyelaraskan keputusan statistik ML dan evaluasi kualitatif LLM menjadi konsensus keamanan terpadu.
- **Generator Laporan PDF Forensik (Bab 11)**: Menghasilkan dokumen audit PDF resmi dengan checksum integritas SHA-256 dan verifikasi analis ganda.

---

## 📚 Sumber Korpus, Dataset & Sitasi Ilmiah Resmi

Seluruh model dalam sistem PhisGuard dilatih dan divalidasi menggunakan dataset dan korpus nyata yang dapat diverifikasi secara publik:

### 1. Korpus Email Phishing Global (17.510 Sampel)
* **Dataset**: *Phishing Email Dataset (Compilation)*
* **Penyedia / Repositori**: [Hugging Face Hub (`zefang-liu/phishing-email-dataset`)](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
* **Komposisi Korpus**:
  1. **Jose Nazario Phishing Corpus**: Arsip ribuan email phishing dunia nyata yang dihimpun oleh peneliti Dr. Jose Nazario.  
     Tautan: [https://monkey.org/~jose/phishing/](https://monkey.org/~jose/phishing/)
  2. **Apache SpamAssassin Public Corpus**: Arsip publik pesan spam & phishing resmi dari Apache Software Foundation.  
     Tautan: [https://spamassassin.apache.org/old/publiccorpus/](https://spamassassin.apache.org/old/publiccorpus/)
  3. **TREC (Text REtrieval Conference) Public Spam Corpus**: Standar pengujian evaluasi akademis National Institute of Standards and Technology (NIST).  
     Tautan: [https://plg.uwaterloo.ca/~gvcormac/treccorpus/](https://plg.uwaterloo.ca/~gvcormac/treccorpus/)

### 2. Korpus Validasi Email Kantor Bersih / Ham (Out-of-Distribution Benchmark)
* **Dataset**: *Enron Email Corpus*
* **Penyedia**: [Hugging Face Hub (`SetFit/enron_spam`)](https://huggingface.co/datasets/SetFit/enron_spam) & Carnegie Mellon University
* **Tautan Resmi**: [https://www.cs.cmu.edu/~enron/](https://www.cs.cmu.edu/~enron/)
* **Kegunaan**: Menguji ketahanan model agar tidak menghasilkan *False Positive* pada percakapan korporat dan operasional kantor yang sah.

### 3. Korpus Ancaman Siber Lokal Indonesia (Threat Intelligence Curation)
Dikurasi dari insiden rekayasa sosial nyata dan security advisory resmi di Indonesia:
* **BSSN (Badan Siber dan Sandi Negara)**: Laporan Tahunan Anomali Siber & Peringatan Keamanan Insiden Phishing & Malware APK.  
  Tautan: [https://www.bssn.go.id](https://www.bssn.go.id)
* **BCA Edukasi Keamanan (Awas Modus)**: Arsip pola penipuan pemblokiran rekening m-BCA, perubahan tarif, dan sniffing PIN/OTP.  
  Tautan: [https://www.bca.co.id/id/edukasi-keamanan/Awas-Modus](https://www.bca.co.id/id/edukasi-keamanan/Awas-Modus)
* **Direktorat Tindak Pidana Siber Bareskrim Polri (Patroli Siber)**: Himbauan penipuan phishing berkedok file resi kurir paket APK (SiCepat/J&T) dan surat tilang elektronik (ETLE).  
  Tautan: [https://patrolisiber.id](https://patrolisiber.id)
* **Direktorat Jenderal Pajak (DJP)**: Siaran Pers Peringatan Penipuan Email Tagihan / Kurang Bayar Pajak & e-Billing Fiktif.  
  Tautan: [https://pajak.go.id/id/siaran-pers](https://pajak.go.id/id/siaran-pers)

### 4. Dataset Tautan URL (100.871 Sampel)
* **LegitPhish Dataset**: Mendeley Data oleh Dr. A. Hannousse & S. Yahi (2021).  
  Tautan: [https://data.mendeley.com/datasets/hx4m73v2sf/2](https://data.mendeley.com/datasets/hx4m73v2sf/2)  
  *Sitasi*: Hannousse, A., & Yahi, S. (2021). *Web page classification for phishing detection using lexical and structural features*. Mendeley Data, V2.
* **ISCX-URL2016 Benchmark**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick.  
  Tautan: [https://www.unb.ca/cic/datasets/url-2016.html](https://www.unb.ca/cic/datasets/url-2016.html)
* **OpenPhish Live Community Threat Feed**:  
  Tautan: [https://openphish.com/feed.txt](https://openphish.com/feed.txt)
* **Cisco Umbrella Top 1 Million Domains**:  
  Tautan: [http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip)

---

## 🖥️ Halaman Aplikasi

| Halaman | Rute | Deskripsi |
| :--- | :--- | :--- |
| **Dashboard** | `/` | Ringkasan statistik aktivitas, rasio ancaman dinamis, dan log audit cepat. |
| **Scan Ancaman** | `/scan` | Formulir pemeriksaan URL & Email dengan Live Forensic Terminal Qwen 2.5 7B. |
| **Hasil Investigasi** | `/result` | Laporan konsensus, status ancaman, evaluasi taktik rekayasa sosial Qwen, dan unduh PDF Bab 11. |
| **Transparansi AI** | `/analysis` | Inspeksi Evidence Bundle terstruktur dan matriks rekonsiliasi Bab 10. |
| **Riwayat (Audit Trail)**| `/history` | Log pemeriksaan persisten dengan fitur hapus terpilih & hapus semua. |
| **Evaluasi Akurasi** | `/evaluation`| Metrik performa (Precision, Recall, F1, Confusion Matrix, OOD Stress-Test). |
| **Pengaturan** | `/settings` | Konfigurasi server Ollama, latensi ping ms, ambang batas sensitivitas ML, dan mode Qwen. |

---

## 📁 Struktur Direktori

```text
PhisLess/
├── models/                       # Bobot model terlatih
│   ├── email/                    # Bilingual SVM & TF-IDF Vectorizer
│   └── url/                      # XGBoost & Random Forest Baseline
├── static/                       # Aset frontend (CSS, JS, SVG)
│   ├── css/
│   ├── img/
│   └── js/
├── templates/                    # Template Jinja2 antarmuka web
│   ├── base.html
│   ├── dashboard.html
│   ├── scanner.html
│   ├── result.html
│   ├── analysis.html
│   ├── history.html
│   ├── evaluation.html
│   └── settings.html
├── app.py                        # Server Flask utama & routing
├── ml_engine.py                  # Pipeline ekstraksi fitur, ML Tier-1 & Qwen Tier-2
├── pdf_report.py                 # Generator Laporan Forensik PDF Resmi (Bab 11)
├── chat.py                       # Terminal interaktif pengujian Qwen 2.5 7B
├── Procfile                      # Konfigurasi deployment cloud (Gunicorn)
├── requirements.txt              # Daftar pustaka Python produksi
├── .gitignore
└── README.md
```

---

## 🚀 Cara Menjalankan

1. **Install dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Jalankan aplikasi Flask**:
   ```bash
   python app.py
   ```

3. **Buka di browser**:
   Akses alamat: **`http://127.0.0.1:5000/`**

---

## 📄 Lisensi & Integritas Akademik
Dikembangkan untuk keperluan edukasi dan riset mata kuliah Keamanan Informasi, Program Studi Informatika, Universitas Siliwangi. Seluruh data, naskah kurasi, dan kode sumber digunakan murni untuk keperluan defensif (*Defensive AI*).
