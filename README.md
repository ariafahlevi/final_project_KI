# 🛡️ PhisGuard: Hybrid Phishing Detection & Verification System

> **Sistem Pertahanan Siber Hybrid: Machine Learning (XGBoost & Linear SVM) + Local LLM (Qwen 2.5 7B via Ollama)**  
> *Final Project Mata Kuliah Keamanan Informasi — Program Studi Informatika, Universitas Siliwangi*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![ML Engine](https://img.shields.io/badge/ml-XGBoost%20%7C%20Linear%20SVM-orange.svg)]()
[![Local LLM](https://img.shields.io/badge/llm-Qwen%202.5%207B%20(Ollama)-purple.svg)]()
[![UI Style](https://img.shields.io/badge/design-Mint%20Sage%20Theme-2e6659.svg)](static/css/style.css)

---

## 📌 Konsep & Arsitektur Sistem

Sistem ini mengimplementasikan prinsip **Defensive AI** dengan mekanisme **Double-Check Independen dan Rekonsiliasi**:

```text
               ┌──────────────────────────────┐
               │    INPUT: URL / Email Teks   │
               └──────────────┬───────────────┘
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
   ┌───────────────────┐             ┌───────────────────┐
   │ 1. DETEKTOR UTAMA │             │ 2. SAFE EVIDENCE  │
   │   (MACHINE LEARN) │             │    INSPECTION     │
   │  - URL: XGBoost   │             │  - HTML / Headers │
   │  - Email: SVM     │             │  - Leksikal / TLD │
   └─────────┬─────────┘             └─────────┬─────────┘
             │ (Label & Probabilitas)          │ (Evidence Bundle)
             │                                 ▼
             │                       ┌───────────────────┐
             │                       │ 3. BLIND VERIFIER │
             │                       │   (QWEN 2.5 7B)   │
             │                       │   via Ollama      │
             │                       └─────────┬─────────┘
             │                                 │ (Second Verdict)
             ▼                                 ▼
   ┌─────────────────────────────────────────────────────┐
   │             4. RECONCILIATION ENGINE                │
   │  - Agree: Konfirmasi Kuat (Phishing / Legitimate)   │
   │  - Disagree: Flag Review Manual                     │
   │  - Warning: Potensi False Negative Detektor ML      │
   └──────────────────────────┬──────────────────────────┘
                              ▼
   ┌─────────────────────────────────────────────────────┐
   │          5. SECURITY INVESTIGATION REPORT           │
   │      Dashboard • Laporan Rinci • Rekomendasi        │
   └─────────────────────────────────────────────────────┘
```

1. **Detektor Pertama (Machine Learning)**:
   - **URL Classifier**: Model produksi **XGBoost Classifier** dilatih pada 17 fitur leksikal dan struktural (akurasi in-distribution **99.95%**, F1 **0.9996**).
   - **Email Classifier**: Model produksi **Calibrated Linear SVM (Platt Scaling)** dengan representasi TF-IDF 25.000 n-gram (akurasi in-distribution **98.97%**, F1 **0.9863**).
2. **Pemeriksa Kedua Independen (Qwen 2.5 7B via Ollama)**:
   - Mengevaluasi konten secara independen tanpa melihat label awal dari ML (*blind evaluation*) untuk mengeliminasi *anchoring bias*.
3. **Modul Rekonsiliasi**:
   - Membandingkan verdict ML vs Qwen: Menandai status *Sepakat*, *Tidak Sepakat*, atau *Peringatan False Negative*.

---

## 🖥️ Halaman Antarmuka Web

| Halaman | Rute | Fitur Utama |
| :--- | :--- | :--- |
| **Dashboard** | `/` | Ikhtisar aktivitas deteksi, grafik tren 7 hari, dan rasio distribusi keamanan. |
| **Scan Ancaman** | `/scan` | Dual-tab scanning: Pemindai URL (XGBoost) & Pemindai Teks Email (Linear SVM) dengan tombol uji cepat. |
| **Hasil Deteksi** | `/result` | Kartu komparasi Double-Check (ML vs Qwen 2.5 7B), rincian 17 fitur teknis, dan rekomendasi mitigasi. |
| **AI Analysis** | `/analysis` | Narasi verifikasi mendalam dari model bahasa Qwen 2.5 7B dengan identifikasi indikator ancaman. |
| **Riwayat** | `/history` | Log aktivitas riwayat scan per sesi pengguna dengan tombol pembersih data. |
| **Evaluasi Model** | `/evaluation` | Tabulasi metrik performa aktual (Accuracy, Precision, Recall, F1), Confusion Matrix, serta evaluasi OOD (OpenPhish & Enron). |
| **Pengaturan** | `/settings` | Konfigurasi tampilan dan status lingkungan aplikasi. |

---

## 📁 Struktur Direktori

```text
PhisLess/
├── models/                       # Artefak Model Machine Learning Terlatih
│   ├── url/
│   │   ├── xgb_production_url.joblib      <- Model produksi XGBoost 17 fitur
│   │   └── rf_baseline_url.joblib         <- Model baseline Random Forest
│   └── email/
│       ├── svm_production_email.joblib    <- Model produksi Calibrated Linear SVM
│       ├── tfidf_vectorizer_email.joblib  <- Fitted TF-IDF Vectorizer (25k n-grams)
│       └── lr_baseline_email.joblib       <- Model baseline Logistic Regression
├── static/
│   ├── css/
│   │   ├── style.css             # Tema Mint Sage responsif
│   │   └── branding.css          # Styling brand mark & tombol uji cepat
│   ├── img/
│   │   └── phishguard-mark.svg   # Ikon resmi PhisGuard
│   └── js/
│       └── app.js                # Handler interaksi form & submit scan
├── templates/                    # Template Jinja2
│   ├── base.html
│   ├── dashboard.html
│   ├── scanner.html
│   ├── result.html
│   ├── analysis.html
│   ├── history.html
│   ├── evaluation.html
│   └── settings.html
├── app.py                        # Entry point server Flask & routing
├── ml_engine.py                  # Pipeline ekstraksi fitur, inferensi ML, & Qwen verifier
├── requirements.txt              # Dependensi Python
├── .gitignore
└── README.md
```

---

## 🚀 Panduan Instalasi & Menjalankan

### Prasyarat
- **Python 3.10+**
- (Opsional untuk LLM Lokal): **Ollama** dengan model Qwen: `ollama pull qwen2.5:7b`

---

### Cara Menjalankan

1. **Aktifkan virtual environment (opsional)**:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   # source .venv/bin/activate # Linux/macOS
   ```

2. **Install dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Jalankan aplikasi**:
   ```bash
   python app.py
   ```

4. Buka di browser: **`http://127.0.0.1:5000/`**
   ```bash
   python app.py
   ```

4. Akses melalui peramban: **`http://127.0.0.1:5000/`**

---

## 📊 Kinerja Model Berdasarkan Pengujian Empiris

| Modul | Model | Accuracy | Precision | Recall | F1-Score | Validasi Eksternal (OOD) |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **URL** | **XGBoost (17 Fitur)** | **99.95%** | **0.9994** | **0.9998** | **0.9996** | OpenPhish Live: Recall 93.00% |
| **Email** | **Calibrated Linear SVM** | **98.97%** | **0.9863** | **0.9863** | **0.9863** | Enron Unseen: Akurasi 99.00% (FP 1.39%) |

---

## 📄 Lisensi & Kontribusi
Dikembangkan sebagai bagian dari proyek akhir mata kuliah Keamanan Informasi. Bebas dipelajari dan dikembangkan lebih lanjut.
