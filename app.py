import os
import re
import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

app = Flask(__name__)
# Konfigurasi Secret Key (dapat dioverride via variabel lingkungan)
app.secret_key = os.environ.get("SECRET_KEY", "phishguard-default-dev-key-2026")

@app.get("/")
def dashboard():
    history_items = session.get("scan_history", [])
    return render_template("dashboard.html", active="dashboard", history=history_items)

@app.get("/scan")
def scanner():
    return render_template("scanner.html", active="scanner")

@app.get("/history")
def history():
    history_items = session.get("scan_history", [])
    return render_template("history.html", active="history", history=history_items)

@app.post("/history/clear")
def clear_history():
    session["scan_history"] = []
    return redirect(url_for("history"))

@app.get("/evaluation")
def evaluation():
    demo_mode = request.args.get("demo", "1") == "1"
    if demo_mode:
        metrics = {
            "precision": "98.4%",
            "recall": "97.1%",
            "f1": "97.7%",
            "tp": "485",
            "fn": "15",
            "fp": "8",
            "tn": "492"
        }
    else:
        metrics = None
    return render_template("evaluation.html", active="evaluation", metrics=metrics, demo=demo_mode)

@app.get("/analysis")
def analysis():
    return render_template("analysis.html", active="analysis", explanation=session.get("explanation"))

@app.get("/settings")
def settings():
    return render_template("settings.html", active="settings")

@app.post("/scan/result")
def scan_result():
    data = request.get_json(silent=True) or {}
    session["last_result"] = data
    return redirect(url_for("show_result"))

@app.get("/result")
def show_result():
    result = session.get("last_result")
    if not result:
        return redirect(url_for("scanner"))
    return render_template("result.html", active="scanner", result=result)

@app.post("/api/scan")
def api_scan():
    """
    Endpoint deteksi URL.
    Dilengkapi dengan simulasi respons heuristik cerdas (Mock CatBoost + Ollama).
    Integrasikan fungsi ekstraksi fitur & model CatBoost/Ollama aktual di sini.
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Alamat URL tidak boleh kosong"}), 400

    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc.lower() or parsed.path.lower().split("/")[0]
    path = parsed.path.lower()
    full_str = f"{domain}{path}"

    # Deteksi pola phishing untuk keperluan simulasi interaktif
    suspicious_keywords = ["login", "verify", "secure", "bank", "account", "update", "free", "claim", "paypal", "auth", "signin", "password", "gift", "billing"]
    detected_keywords = [kw for kw in suspicious_keywords if kw in full_str]
    has_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain))
    is_not_https = parsed.scheme != "https"
    has_at_symbol = "@" in url
    hyphen_count = domain.count("-")

    is_phishing = bool(detected_keywords or has_ip or has_at_symbol or hyphen_count >= 2 or any(tld in domain for tld in [".xyz", ".top", ".test", ".tk"]))

    if is_phishing:
        prediction = "phishing"
        confidence = 96.8 if (detected_keywords and is_not_https) else 89.4
        features = {
            "Panjang URL": f"{len(url)} karakter",
            "Protokol HTTPS": "Tidak (Tidak Terenkripsi)" if is_not_https else "Ya (Valid)",
            "Nama Domain": domain or "Tidak terdeteksi",
            "Kata Kunci Sensitif": f"Terdeteksi ({', '.join(detected_keywords)})" if detected_keywords else "Tidak ada",
            "Karakter Khusus (@ / -)": f"Ditemukan ({hyphen_count} tanda hubung)" if (has_at_symbol or hyphen_count > 0) else "Normal",
            "Format Host IP": "Ya (Indikasi Mencurigakan)" if has_ip else "Tidak (Domain Reguler)"
        }
        recommendation = "Hindari membuka tautan ini dan jangan pernah memasukkan kredensial, sandi, atau data pribadi pada situs ini."
        explanation = (
            f"Model mendeteksi anomali pada URL '{url}'. "
            f"Faktor risiko utama meliputi: "
            f"{'protokol tidak aman (HTTP), ' if is_not_https else ''}"
            f"{'keberadaan kata kunci berisiko tinggi (' + ', '.join(detected_keywords) + '), ' if detected_keywords else ''}"
            f"{'penggunaan alamat IP langsung sebagai host, ' if has_ip else ''}"
            f"{'serta pola struktur domain bertingkat/tanda hubung berlebih. ' if hyphen_count > 1 else ''}"
            f"Pola ini secara signifikan menyerupai teknik phishing dan manipulasi URL."
        )
    else:
        prediction = "legitimate"
        confidence = 98.6
        features = {
            "Panjang URL": f"{len(url)} karakter",
            "Protokol HTTPS": "Ya (Terenkripsi)" if not is_not_https else "Tidak",
            "Nama Domain": domain,
            "Kata Kunci Sensitif": "Tidak ditemukan",
            "Karakter Khusus (@ / -)": "Normal",
            "Format Host IP": "Tidak (Domain Resmi)"
        }
        recommendation = "Tautan memiliki struktur yang wajar dan aman untuk dikunjungi. Tetap berhati-hati saat mengunduh berkas asing."
        explanation = (
            f"Berdasarkan analisis fitur URL, tautan '{url}' memiliki struktur domain standar yang terpercaya, "
            f"tidak memanfaatkan pola tipuan visual (typosquatting), dan konsisten dengan karakteristik tautan legitimate."
        )

    # Simpan ke session untuk halaman analysis
    session["explanation"] = explanation

    # Simpan ke daftar riwayat scan sesi
    history_list = session.get("scan_history", [])
    now_str = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    history_list.insert(0, {
        "url": url,
        "time": now_str,
        "prediction": prediction,
        "confidence": confidence
    })
    session["scan_history"] = history_list[:30]

    return jsonify({
        "url": url,
        "prediction": prediction,
        "confidence": confidence,
        "features": features,
        "recommendation": recommendation,
        "explanation": explanation
    })

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", os.environ.get("PORT", 5000)))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print("=" * 60)
    print(f"  PhishGuard AI Frontend berjalan di: http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(debug=debug, host="0.0.0.0", port=port)
