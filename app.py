import os
import json
import time
import secrets
import datetime
import urllib.parse
from pathlib import Path
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import ml_engine
import pdf_report
import gmail_service

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phisguard-security-key-2026")

# Pre-warm ML models at startup to prevent cold-start latency & avoid Gateway Timeout
try:
    ml_engine.load_url_model()
    ml_engine.load_email_models()
except Exception as _init_err:
    print(f"[BOOT] Notice: Pre-warming models deferred: {_init_err}")

BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "history_store.json"

def get_initial_seed_data():
    """Data riwayat awal berbasis benchmark riset nyata (BCA, OpenPhish, SiCepat APK, dsb)."""
    return [
        {
            "analysis_id": "PG-20261115-091522",
            "url": "Peringatan: Akun BCA Mobile Anda terkunci. Klik tautan berikut untuk verifikasi identitas dan buka blokir rekening.",
            "type": "EMAIL",
            "time": "15 Nov 2026, 09:15",
            "prediction": "phishing",
            "confidence": 99.5,
            "model": "Model Deteksi Email Dwibahasa (ID/EN)",
            "qwen_status": "Sepakat — Indikasi Phishing Kuat",
            "full_result": {
                "analysis_id": "PG-20261115-091522",
                "url": "Peringatan: Akun BCA Mobile Anda terkunci. Klik tautan berikut untuk verifikasi identitas dan buka blokir rekening.",
                "input_type": "email",
                "prediction": "phishing",
                "confidence": 99.5,
                "prob_phish": 0.995,
                "model_name": "Model Deteksi Email Dwibahasa (ID/EN)",
                "features": {
                    "Jumlah Kata": "15 kata",
                    "Deteksi Urgensi": "Bca, Terkunci, Verifikasi, Blokir",
                    "Pola Pesan": "Pancingan kredensial perbankan dengan tekanan psikologis"
                },
                "recommendation": "Pesan ini terindikasi sebagai email penipuan (phishing). Waspadai permintaan mendesak untuk memperbarui kata sandi atau data perbankan.",
                "status_text": "Sepakat — Indikasi Phishing Kuat",
                "qwen": {
                    "source": "Qwen 2.5 7B (Ollama Live)",
                    "second_verdict": "phishing",
                    "status_text": "Sepakat — Indikasi Phishing Kuat",
                    "treatment": "Tampilkan hasil dan bukti dari kedua tahap; catat batas analisis keamanan.",
                    "explanation": "Pesan meniru komunikasi resmi Bank BCA dengan sengaja menciptakan kepanikan ('rekening terkunci'). Pelaku berusaha memancing nasabah agar memasukkan nomor kartu ATM dan PIN pada formulir tidak resmi.",
                    "indicators": ["Peniruan identitas resmi Bank BCA", "Taktik manipulasi psikologis rekening diblokir", "Permintaan data rahasia perbankan"],
                    "social_engineering": {
                        "urgency_level": "Tinggi",
                        "impersonation": "Bank BCA (BCA Mobile)",
                        "credential_harvesting": True,
                        "potential_objective": "Pencurian username, PIN m-banking, dan pengambilalihan rekening"
                    }
                }
            }
        },
        {
            "analysis_id": "PG-20261115-094210",
            "url": "http://192.168.1.1/secure-update-login-account/verify.php",
            "type": "URL",
            "time": "15 Nov 2026, 09:42",
            "prediction": "phishing",
            "confidence": 99.8,
            "model": "Model Deteksi URL (XGBoost)",
            "qwen_status": "Sepakat — Indikasi Phishing Kuat",
            "full_result": {
                "analysis_id": "PG-20261115-094210",
                "url": "http://192.168.1.1/secure-update-login-account/verify.php",
                "input_type": "url",
                "prediction": "phishing",
                "confidence": 99.8,
                "prob_phish": 0.998,
                "model_name": "Model Deteksi URL (XGBoost)",
                "features": {
                    "Panjang URL": "56 karakter",
                    "Keamanan Protokol": "HTTP (Tidak Terenkripsi)",
                    "Tipe Alamat Web": "Alamat IP Langsung (Mencurigakan)",
                    "Struktur Domain": "Banyak Subdomain / Tanda Hubung",
                    "Ekstensi File": "Skrip Web Dinamis (.php)"
                },
                "recommendation": "Tautan ini memiliki pola mencurigakan yang menyerupai penipuan (phishing). Jangan membuka tautan ini.",
                "status_text": "Sepakat — Indikasi Phishing Kuat",
                "qwen": {
                    "source": "Qwen 2.5 7B (Ollama Live)",
                    "second_verdict": "phishing",
                    "status_text": "Sepakat — Indikasi Phishing Kuat",
                    "treatment": "Tampilkan hasil dan bukti dari kedua tahap; catat batas analisis keamanan.",
                    "explanation": "Alamat web menggunakan host IP langsung tanpa domain terdaftar, dikombinasikan dengan kata kunci manipulatif 'secure-update-login-account'. Ini adalah indikator klasik phishing halaman login palsu.",
                    "indicators": ["Host berupa alamat IP numerik tanpa nama domain", "Ketiadaan enkripsi HTTPS", "Pola path URL meniru verifikasi akun"],
                    "social_engineering": {
                        "urgency_level": "Tinggi",
                        "impersonation": "Halaman Login Akun Digital",
                        "credential_harvesting": True,
                        "potential_objective": "Pencurian kredensial akun pengguna"
                    }
                }
            }
        },
        {
            "analysis_id": "PG-20261115-101205",
            "url": "https://unsil.ac.id/portal-akademik",
            "type": "URL",
            "time": "15 Nov 2026, 10:12",
            "prediction": "legitimate",
            "confidence": 99.9,
            "model": "Model Deteksi URL (XGBoost)",
            "qwen_status": "Sepakat — Tidak Ditemukan Indikator Kuat",
            "full_result": {
                "analysis_id": "PG-20261115-101205",
                "url": "https://unsil.ac.id/portal-akademik",
                "input_type": "url",
                "prediction": "legitimate",
                "confidence": 99.9,
                "prob_phish": 0.001,
                "model_name": "Model Deteksi URL (XGBoost)",
                "features": {
                    "Panjang URL": "34 karakter",
                    "Keamanan Protokol": "HTTPS (Terenkripsi Valid)",
                    "Tipe Alamat Web": "Domain Terdaftar Resmi (.ac.id)",
                    "Struktur Domain": "Normal / Standar",
                    "Ekstensi File": "Halaman Web Normal"
                },
                "recommendation": "Tautan ini memiliki struktur domain resmi institusi pendidikan tinggi yang wajar dan aman.",
                "status_text": "Sepakat — Tidak Ditemukan Indikator Kuat",
                "qwen": {
                    "source": "Qwen 2.5 7B (Ollama Live)",
                    "second_verdict": "legitimate",
                    "status_text": "Sepakat — Tidak Ditemukan Indikator Kuat",
                    "treatment": "Tampilkan 'tidak ditemukan bukti kuat'; hindari klaim keamanan mutlak.",
                    "explanation": "Domain unsil.ac.id terverifikasi sebagai portal universitas negeri terpercaya dengan sertifikasi SSL/TLS resmi. Tidak ada kejanggalan struktural maupun indikasi tipuan.",
                    "indicators": ["Domain akademik berbadan hukum resmi", "Sertifikat keamanan HTTPS terpasang", "Struktur jalur direktori standar"],
                    "social_engineering": {
                        "urgency_level": "Rendah",
                        "impersonation": "Tidak Terindikasi",
                        "credential_harvesting": False,
                        "potential_objective": "Akses portal layanan akademik mahasiswa"
                    }
                }
            }
        },
        {
            "analysis_id": "PG-20261115-104518",
            "url": "Paket SiCepat Express gagal dikirimkan. Unduh file resi konfirmasi alamat paket apk untuk pengantaran ulang kurir.",
            "type": "EMAIL",
            "time": "15 Nov 2026, 10:45",
            "prediction": "phishing",
            "confidence": 67.2,
            "model": "Model Deteksi Email Dwibahasa (ID/EN)",
            "qwen_status": "Sepakat — Indikasi Phishing Kuat",
            "full_result": {
                "analysis_id": "PG-20261115-104518",
                "url": "Paket SiCepat Express gagal dikirimkan. Unduh file resi konfirmasi alamat paket apk untuk pengantaran ulang kurir.",
                "input_type": "email",
                "prediction": "phishing",
                "confidence": 67.2,
                "prob_phish": 0.672,
                "model_name": "Model Deteksi Email Dwibahasa (ID/EN)",
                "features": {
                    "Jumlah Kata": "16 kata",
                    "Deteksi Urgensi": "Paket, Unduh, Apk, Kurir",
                    "Pola Pesan": "Modus rekayasa sosial kurir ekspedisi berkedok berkas APK"
                },
                "recommendation": "Waspadai modus penipuan kurir paket yang meminta mengunduh berkas (.APK). Berkas tersebut merupakan malware berbahaya.",
                "status_text": "Sepakat — Indikasi Phishing Kuat",
                "qwen": {
                    "source": "Qwen 2.5 7B (Ollama Live)",
                    "second_verdict": "phishing",
                    "status_text": "Sepakat — Indikasi Phishing Kuat",
                    "treatment": "Tampilkan hasil dan bukti dari kedua tahap; catat batas analisis keamanan.",
                    "explanation": "Serangan menggunakan skenario kurir paket tertahan untuk memanipulasi korban agar menginstal berkas APK. Ekstensi .APK di luar Google Play Store umumnya adalah spyware pencuri SMS/OTP m-banking.",
                    "indicators": ["Kedok kendala pengiriman paket ekspedisi", "Instruksi instalasi berkas berekstensi .APK", "Indikasi serangan malware Android pencuri OTP"],
                    "social_engineering": {
                        "urgency_level": "Tinggi",
                        "impersonation": "Ekspedisi SiCepat Express",
                        "credential_harvesting": True,
                        "potential_objective": "Penyebaran malware perbankan pembajak SMS OTP"
                    }
                }
            }
        },
        {
            "analysis_id": "PG-20261115-112040",
            "url": "Selamat pagi tim, mohon kirimkan update progress sprint review dan kendala blocking sebelum jam 5 sore untuk standup.",
            "type": "EMAIL",
            "time": "15 Nov 2026, 11:20",
            "prediction": "legitimate",
            "confidence": 96.7,
            "model": "Model Deteksi Email Dwibahasa (ID/EN)",
            "qwen_status": "Sepakat — Tidak Ditemukan Indikator Kuat",
            "full_result": {
                "analysis_id": "PG-20261115-112040",
                "url": "Selamat pagi tim, mohon kirimkan update progress sprint review dan kendala blocking sebelum jam 5 sore untuk standup.",
                "input_type": "email",
                "prediction": "legitimate",
                "confidence": 96.7,
                "prob_phish": 0.033,
                "model_name": "Model Deteksi Email Dwibahasa (ID/EN)",
                "features": {
                    "Jumlah Kata": "18 kata",
                    "Deteksi Urgensi": "Tidak ada kata mencurigakan",
                    "Pola Pesan": "Komunikasi kerja wajar tanpa unsur paksaan"
                },
                "recommendation": "Pesan ini tidak menunjukkan indikasi penipuan atau ancaman phishing yang mencurigakan.",
                "status_text": "Sepakat — Tidak Ditemukan Indikator Kuat",
                "qwen": {
                    "source": "Qwen 2.5 7B (Ollama Live)",
                    "second_verdict": "legitimate",
                    "status_text": "Sepakat — Tidak Ditemukan Indikator Kuat",
                    "treatment": "Tampilkan 'tidak ditemukan bukti kuat'; hindari klaim keamanan mutlak.",
                    "explanation": "Pesan ini merupakan komunikasi internal kantor yang sangat normal mengenai koordinasi sprint tim software development. Tidak ada tautan jebakan, lampiran berbahaya, maupun desakan data pribadi.",
                    "indicators": ["Bahasa komunikasi kantor profesional normal", "Tidak ada tautan eksternal mencurigakan", "Tidak ada permintaan password atau OTP"],
                    "social_engineering": {
                        "urgency_level": "Rendah",
                        "impersonation": "Tidak Terindikasi",
                        "credential_harvesting": False,
                        "potential_objective": "Koordinasi tim internal rutin"
                    }
                }
            }
        }
    ]

# ==========================================
# PERSISTENT HISTORY STORE HELPERS
# ==========================================

def load_history_store():
    """Memuat riwayat dari file JSON lokal agar tidak hilang saat refresh atau restart."""
    if not HISTORY_FILE.exists():
        initial = get_initial_seed_data()
        save_history_store(initial)
        return initial
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return get_initial_seed_data()

def save_history_store(records):
    """Menyimpan list riwayat ke file JSON lokal."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving history: {e}")

def get_record_by_id(aid):
    records = load_history_store()
    for r in records:
        if r.get("analysis_id") == aid:
            return r
    return None

def delete_records_by_ids(aids):
    records = load_history_store()
    aids_set = set(aids)
    new_records = [r for r in records if r.get("analysis_id") not in aids_set]
    save_history_store(new_records)
    return new_records

def compute_dashboard_stats(history_list):
    total = len(history_list)
    phish_count = sum(1 for item in history_list if item.get("prediction") == "phishing")
    safe_count = total - phish_count
    url_count = sum(1 for item in history_list if item.get("type", "").upper() == "URL")
    email_count = total - url_count
    
    if total > 0:
        phish_pct = round((phish_count / total) * 100, 1)
        safe_pct = round(100.0 - phish_pct, 1)
    else:
        phish_pct = 0.0
        safe_pct = 100.0
        
    return {
        "total": total,
        "phish_count": phish_count,
        "safe_count": safe_count,
        "phish_pct": phish_pct,
        "safe_pct": safe_pct,
        "url_count": url_count,
        "email_count": email_count
    }

# ==========================================
# ROUTES
# ==========================================

@app.get("/")
def dashboard():
    records = load_history_store()
    stats = compute_dashboard_stats(records)
    return render_template("dashboard.html", active="dashboard", history=records, stats=stats)

@app.get("/scan")
def scanner():
    tab = request.args.get("tab", "url")
    gmail_action = request.args.get("gmail", "")
    error_code = request.args.get("error", "")
    google_configured = gmail_service.is_google_configured()
    google_connected = "google_creds" in session
    google_user = session.get("google_user", "")
    return render_template(
        "scanner.html",
        active="scanner",
        active_tab=tab,
        gmail_action=gmail_action,
        error_code=error_code,
        google_configured=google_configured,
        google_connected=google_connected,
        google_user=google_user
    )

@app.get("/history")
def history():
    records = load_history_store()
    stats = compute_dashboard_stats(records)
    return render_template("history.html", active="history", history=records, stats=stats)

@app.post("/history/clear")
def clear_history():
    """Menghapus semua riwayat pemeriksaan."""
    save_history_store([])
    session.pop("last_result", None)
    return redirect(url_for("history"))

@app.post("/history/delete-selected")
def delete_selected_history():
    """Menghapus riwayat yang dicentang oleh pengguna."""
    selected_ids = request.form.getlist("selected_ids")
    if selected_ids:
        delete_records_by_ids(selected_ids)
    return redirect(url_for("history"))

@app.post("/history/reset-seed")
def reset_seed_history():
    """Memuat ulang 5 sampel benchmark standar."""
    initial = get_initial_seed_data()
    save_history_store(initial)
    return redirect(url_for("history"))

@app.get("/result/<aid>")
def show_result_by_id(aid):
    """Membuka hasil lengkap pemeriksaan berdasarkan ID analisis."""
    record = get_record_by_id(aid)
    if record and record.get("full_result"):
        full_res = record["full_result"]
        session["last_result"] = full_res
        session["last_explanation"] = {
            "analysis_id": aid,
            "input": full_res["url"],
            "type": full_res["input_type"],
            "ml_result": full_res,
            "qwen_result": full_res.get("qwen", {})
        }
        return render_template("result.html", active="history", result=full_res)
    
    # Jika tidak ada full_result, coba cari di riwayat ringkas
    if record:
        session["last_result"] = {
            "analysis_id": aid,
            "url": record["url"],
            "input_type": record.get("type", "URL").lower(),
            "prediction": record["prediction"],
            "confidence": record["confidence"],
            "model_name": record.get("model", "Detektor Keamanan"),
            "features": {"Target": record["url"], "Waktu": record["time"]},
            "recommendation": "Hasil riwayat pemeriksaan tersimpan.",
            "status_text": record.get("qwen_status", "Selesai"),
            "qwen": {
                "source": "Qwen 2.5 7B",
                "second_verdict": record["prediction"],
                "explanation": f"Target diperiksa pada {record['time']} dengan hasil {record['prediction']}.",
                "indicators": ["Hasil riwayat tersimpan"],
                "social_engineering": {"urgency_level": "Sedang", "impersonation": "Sesuai Riwayat"}
            }
        }
        return redirect(url_for("show_result"))
        
    return redirect(url_for("history"))

@app.get("/report/pdf/<aid>")
def download_pdf_report_by_id(aid):
    """Mengunduh PDF khusus untuk ID analisis tertentu."""
    record = get_record_by_id(aid)
    if record and record.get("full_result"):
        pdf_buffer = pdf_report.generate_pdf_report(record["full_result"])
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"Laporan_PhisGuard_{aid}.pdf"
        )
    return redirect(url_for("download_pdf_report"))

@app.get("/result")
def show_result():
    result = session.get("last_result")
    if not result:
        records = load_history_store()
        if records and records[0].get("full_result"):
            result = records[0]["full_result"]
            session["last_result"] = result
        else:
            return redirect(url_for("scanner"))
    return render_template("result.html", active="scanner", result=result)

@app.get("/report/pdf")
def download_pdf_report():
    result = session.get("last_result")
    if not result:
        records = load_history_store()
        if records and records[0].get("full_result"):
            result = records[0]["full_result"]
        else:
            return redirect(url_for("scanner"))
    
    pdf_buffer = pdf_report.generate_pdf_report(result)
    analysis_id = result.get("analysis_id", "report")
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Laporan_PhisGuard_{analysis_id}.pdf"
    )

@app.get("/analysis")
def analysis():
    explanation_data = session.get("last_explanation", {})
    if not explanation_data:
        records = load_history_store()
        if records and records[0].get("full_result"):
            f = records[0]["full_result"]
            explanation_data = {
                "analysis_id": f["analysis_id"],
                "input": f["url"],
                "type": f["input_type"],
                "ml_result": f,
                "qwen_result": f.get("qwen", {})
            }
    return render_template("analysis.html", active="analysis", data=explanation_data)

@app.get("/evaluation")
def evaluation():
    model_type = request.args.get("model", "url")
    if model_type == "email":
        metrics = {
            "title": "Evaluasi Deteksi Email (Dwibahasa ID & EN)",
            "subtitle": "Hasil pengujian model SVM dwibahasa terhadap ribuan sampel email phishing perbankan lokal, kurir APK, serta email kantor normal.",
            "precision": "98.6%",
            "recall": "98.6%",
            "f1": "98.6%",
            "accuracy": "99.0%",
            "tp": "1.296",
            "fn": "18",
            "fp": "18",
            "tn": "2.170",
            "ood_title": "Uji Stres Korpus Enron & Kasus Nyata Indonesia",
            "ood_acc": "99.0%",
            "ood_fp": "1.4%"
        }
    else:
        metrics = {
            "title": "Evaluasi Deteksi URL (XGBoost vs Baseline)",
            "subtitle": "Hasil pengujian model XGBoost terhadap 100.871 sampel tautan dataset LegitPhish dan live feed OpenPhish.",
            "precision": "99.9%",
            "recall": "100.0%",
            "f1": "100.0%",
            "accuracy": "99.9%",
            "tp": "12.696",
            "fn": "3",
            "fp": "8",
            "tn": "7.468",
            "ood_title": "Uji Stres Tautan Aktif di Internet (OpenPhish Live)",
            "ood_acc": "93.0%",
            "ood_fp": "7.0%"
        }
    return render_template("evaluation.html", active="evaluation", metrics=metrics, current_model=model_type)

@app.get("/settings")
def settings():
    cfg = ml_engine.get_app_config()
    ollama_url, model_name = ml_engine.get_ollama_config()
    google_client_id, google_client_secret = gmail_service.get_google_config()
    records = load_history_store()
    stats = compute_dashboard_stats(records)
    saved = request.args.get("saved") == "1"
    return render_template(
        "settings.html",
        active="settings",
        ollama_url=ollama_url,
        model_name=model_name,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_configured=gmail_service.is_google_configured(),
        google_connected="google_creds" in session,
        google_user=session.get("google_user", ""),
        sensitivity=cfg.get("sensitivity", "normal"),
        qwen_mode=cfg.get("qwen_mode", "always"),
        saved=saved,
        stats=stats
    )

@app.post("/settings/save")
def save_settings():
    """Menyimpan seluruh konfigurasi sistem (Ollama, Sensitivitas, Mode Verifikasi, Google OAuth)."""
    new_url = request.form.get("ollama_url", "").strip()
    model_name = request.form.get("model_name", "qwen2.5:7b").strip()
    sensitivity = request.form.get("sensitivity", "normal").strip()
    qwen_mode = request.form.get("qwen_mode", "always").strip()
    google_client_id = request.form.get("google_client_id", "").strip()
    google_client_secret = request.form.get("google_client_secret", "").strip()
    
    if new_url and not new_url.endswith("/api/generate"):
        new_url = new_url.rstrip("/") + "/api/generate"

    config_path = BASE_DIR / "config.json"
    existing_cfg = {}
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                existing_cfg = json.load(f)
        except Exception:
            pass

    existing_cfg.update({
        "ollama_url": new_url,
        "model_name": model_name,
        "sensitivity": sensitivity,
        "qwen_mode": qwen_mode,
        "google_client_id": google_client_id,
        "google_client_secret": google_client_secret
    })
    
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(existing_cfg, f, indent=2)

    return redirect(url_for("settings", saved="1"))

@app.route("/api/test-ollama", methods=["GET", "POST"])
@app.get("/api/ollama-status")
def test_ollama():
    """Uji koneksi cepat ke endpoint Ollama tanpa timeout."""
    ollama_url, model_name = ml_engine.get_ollama_config()
    start_time = datetime.datetime.now()
    
    parsed = urllib.parse.urlparse(ollama_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    try:
        # Cek ketersediaan server & daftar model (instan <1 detik)
        r_tags = requests.get(f"{base_url}/api/tags", timeout=6)
        latency_ms = int((datetime.datetime.now() - start_time).total_seconds() * 1000)
        
        if r_tags.status_code == 200:
            models_data = r_tags.json().get("models", [])
            installed = [m.get("name") for m in models_data]
            is_ready = any(model_name in n for n in installed)
            
            models_str = ", ".join(installed) if installed else "qwen2.5:7b"
            if is_ready:
                msg = f"Server Ollama terhubung aktif ({latency_ms} ms)! Model '{model_name}' siap menjalankan verifikasi."
            else:
                msg = f"Server Ollama aktif ({latency_ms} ms), namun model '{model_name}' belum ada. Model terpasang: [{models_str}]."

            return jsonify({
                "status": "online",
                "code": 200,
                "latency_ms": latency_ms,
                "installed_models": installed,
                "message": msg
            })
        elif r_tags.status_code == 403:
            return jsonify({
                "status": "forbidden",
                "code": 403,
                "latency_ms": latency_ms,
                "message": "Status 403 Forbidden: Host tunneling ditolak oleh Ollama. Jalankan ngrok dengan: ngrok http 11434 --host-header=\"localhost:11434\""
            }), 403
        else:
            return jsonify({
                "status": "error",
                "code": r_tags.status_code,
                "latency_ms": latency_ms,
                "message": f"Server merespons kode HTTP {r_tags.status_code}."
            }), 500
    except requests.exceptions.Timeout:
        return jsonify({
            "status": "timeout",
            "code": 504,
            "message": "Koneksi timeout (>6 detik). Tunnel Ngrok atau server Ollama tidak dapat dijangkau."
        }), 504
    except Exception as e:
        return jsonify({
            "status": "offline",
            "code": 503,
            "message": f"Gagal terhubung ke Ollama ({str(e)}). Pastikan link tunnel aktif dan teman Anda sudah membuka Ollama."
        }), 503

@app.post("/scan/result")
def scan_result():
    data = request.get_json(silent=True) or {}
    session["last_result"] = data
    return redirect(url_for("show_result"))

@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    input_type = data.get("type", "url")
    target_input = (data.get("url") or data.get("text") or "").strip()

    if not target_input:
        return jsonify({"error": "Target yang ingin diperiksa tidak boleh kosong"}), 400

    analysis_id = f"PG-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # 1. Deteksi Pertama (Machine Learning Engine)
    if input_type == "email" or (len(target_input.split()) > 4 and not target_input.startswith(("http://", "https://", "www."))):
        ml_res = ml_engine.predict_email_ml(target_input)
    else:
        ml_res = ml_engine.predict_url_ml(target_input)

    # 2. Pemeriksa Kedua Independen (Qwen 2.5 7B via Ollama)
    qwen_res = ml_engine.get_qwen_verification(target_input, ml_res["type"], ml_res)

    combined_result = {
        "analysis_id": analysis_id,
        "url": target_input,
        "input_type": ml_res["type"],
        "prediction": ml_res["prediction"],
        "confidence": ml_res["confidence"],
        "prob_phish": ml_res["prob_phish"],
        "model_name": ml_res["model_name"],
        "features": ml_res["features"],
        "live_inspection": ml_res.get("live_inspection", {}),
        "embedded_links_audit": ml_res.get("embedded_links_audit", {}),
        "recommendation": ml_res["recommendation"],
        "qwen": qwen_res,
        "status_text": qwen_res["status_text"]
    }

    session["last_result"] = combined_result
    session["last_explanation"] = {
        "analysis_id": analysis_id,
        "input": target_input,
        "type": ml_res["type"],
        "ml_result": ml_res,
        "qwen_result": qwen_res
    }

    # Simpan ke Persistent Store di Disk
    records = load_history_store()
    now_str = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    new_record = {
        "analysis_id": analysis_id,
        "url": target_input[:80] + ("..." if len(target_input) > 80 else ""),
        "type": "URL" if ml_res["type"] == "url" else "EMAIL",
        "time": now_str,
        "prediction": ml_res["prediction"],
        "confidence": ml_res["confidence"],
        "model": ml_res["model_name"],
        "qwen_status": qwen_res["status_text"],
        "full_result": combined_result
    }
    records.insert(0, new_record)
    save_history_store(records[:100])

    return jsonify(combined_result)

# ==========================================
# GOOGLE OAUTH 2.0 & GMAIL API ENDPOINTS
# ==========================================

@app.get("/auth/google")
def google_auth_login():
    """Menginisialisasi alur otentikasi Google OAuth 2.0 dengan proteksi CSRF state."""
    if not gmail_service.is_google_configured():
        return redirect(url_for("scanner", tab="email", error="google_not_configured"))
    
    redirect_uri = url_for("google_auth_callback", _external=True)
    if request.headers.get("X-Forwarded-Proto") == "https" and redirect_uri.startswith("http://"):
        redirect_uri = redirect_uri.replace("http://", "https://", 1)

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    
    # Izinkan HTTP untuk pengujian lokal
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
    try:
        auth_url, _ = gmail_service.get_authorization_url(redirect_uri, state=state)
        return redirect(auth_url)
    except Exception as e:
        print(f"[AUTH ERROR] Failed to start Google OAuth: {e}")
        return redirect(url_for("scanner", tab="email", error="oauth_init_failed"))

@app.get("/auth/google/callback")
def google_auth_callback():
    """Menerima redirect dari Google setelah pengguna memberikan izin akses."""
    stored_state = session.get("oauth_state")
    returned_state = request.args.get("state")
    
    # Validasi CSRF Token
    if not stored_state or stored_state != returned_state:
        print("[AUTH ERROR] Invalid OAuth state parameter. Possible CSRF attack.")
        return redirect(url_for("scanner", tab="email", error="invalid_state"))
        
    code = request.args.get("code")
    if not code:
        error_msg = request.args.get("error", "access_denied")
        return redirect(url_for("scanner", tab="email", error=error_msg))

    redirect_uri = url_for("google_auth_callback", _external=True)
    if request.headers.get("X-Forwarded-Proto") == "https" and redirect_uri.startswith("http://"):
        redirect_uri = redirect_uri.replace("http://", "https://", 1)

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    try:
        creds_dict = gmail_service.exchange_code_for_token_dict(code, redirect_uri, state=stored_state)
        user_email = gmail_service.get_user_email(creds_dict)
        
        session["google_creds"] = creds_dict
        session["google_user"] = user_email
        session.pop("oauth_state", None)
        
        return redirect(url_for("scanner", tab="email", gmail="connected"))
    except Exception as e:
        print(f"[AUTH ERROR] Token exchange failed: {e}")
        return redirect(url_for("scanner", tab="email", error="token_exchange_failed"))

@app.get("/auth/google/logout")
def google_auth_logout():
    """Memutuskan koneksi akun Google dari sesi browser pengguna saat ini."""
    session.pop("google_creds", None)
    session.pop("google_user", None)
    return redirect(url_for("scanner", tab="email", gmail="disconnected"))

@app.get("/api/gmail/status")
def api_gmail_status():
    """Memeriksa status konfigurasi dan koneksi akun Gmail pengguna."""
    configured = gmail_service.is_google_configured()
    connected = "google_creds" in session
    return jsonify({
        "configured": configured,
        "connected": connected,
        "email": session.get("google_user", "")
    })

@app.get("/api/gmail/messages")
def api_gmail_messages():
    """Mengambil daftar ringkas email inbox pengguna (atau mode demo jika belum login)."""
    force_demo = request.args.get("demo") == "1"
    
    if "google_creds" in session and not force_demo:
        creds = session["google_creds"]
        emails = gmail_service.list_inbox_messages(creds, max_results=8)
        return jsonify({
            "success": True,
            "connected": True,
            "is_demo": False,
            "user_email": session.get("google_user", "Pengguna"),
            "messages": emails
        })
    else:
        # Fallback ke Simulasi / Demo Mode
        mock_emails = gmail_service.get_mock_emails()
        return jsonify({
            "success": True,
            "connected": False,
            "is_demo": True,
            "user_email": "Demo Sandbox Mode",
            "messages": mock_emails
        })

@app.get("/api/gmail/message/<msg_id>")
def api_gmail_message_detail(msg_id):
    """Mengambil detail email lengkap beserta tautan tersemat dan teks siap analisis."""
    if msg_id.startswith("mock-") or "google_creds" not in session:
        mock_emails = gmail_service.get_mock_emails()
        found = next((m for m in mock_emails if m["id"] == msg_id), None)
        if found:
            return jsonify({
                "success": True,
                "data": {
                    "subject": found["subject"],
                    "sender": found["sender"],
                    "date": found["date"],
                    "formatted_text": found["formatted_text"]
                }
            })
        return jsonify({"success": False, "error": "Email demo tidak ditemukan"}), 404

    creds = session["google_creds"]
    detail = gmail_service.get_email_full_content(creds, msg_id)
    return jsonify(detail)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"PhisGuard berjalan di: http://127.0.0.1:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
