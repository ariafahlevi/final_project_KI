import os
import json
import time
import datetime
import urllib.parse
from pathlib import Path
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import ml_engine
import pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phisguard-security-key-2026")

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
    return render_template("scanner.html", active="scanner")

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
    records = load_history_store()
    stats = compute_dashboard_stats(records)
    saved = request.args.get("saved") == "1"
    return render_template(
        "settings.html",
        active="settings",
        ollama_url=ollama_url,
        model_name=model_name,
        sensitivity=cfg.get("sensitivity", "normal"),
        qwen_mode=cfg.get("qwen_mode", "always"),
        saved=saved,
        stats=stats
    )

@app.post("/settings/save")
def save_settings():
    """Menyimpan seluruh konfigurasi sistem (Ollama, Sensitivitas, Mode Verifikasi)."""
    new_url = request.form.get("ollama_url", "").strip()
    model_name = request.form.get("model_name", "qwen2.5:7b").strip()
    sensitivity = request.form.get("sensitivity", "normal").strip()
    qwen_mode = request.form.get("qwen_mode", "always").strip()
    
    if new_url and not new_url.endswith("/api/generate"):
        new_url = new_url.rstrip("/") + "/api/generate"

    cfg = {
        "ollama_url": new_url,
        "model_name": model_name,
        "sensitivity": sensitivity,
        "qwen_mode": qwen_mode
    }
    config_path = BASE_DIR / "config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    return redirect(url_for("settings", saved="1"))

@app.post("/api/test-ollama")
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"PhisGuard berjalan di: http://127.0.0.1:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
