import os
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import ml_engine

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
    # Model evaluasi nyata dari eksperimen training (EXP-001 & EXP-002)
    model_type = request.args.get("model", "url") # 'url' atau 'email'
    
    if model_type == "email":
        metrics = {
            "title": "Evaluasi Model Email: Calibrated Linear SVM",
            "subtitle": "Klasifikasi korpus email phishing berbasis TF-IDF 25.000 n-gram dengan kalibrasi probabilitas sigmoid.",
            "precision": "98.63%",
            "recall": "98.63%",
            "f1": "98.63%",
            "accuracy": "98.97%",
            "tp": "1,296",
            "fn": "18",
            "fp": "18",
            "tn": "2,170",
            "ood_title": "Stress-Test OOD Enron (600 Email Kantor)",
            "ood_acc": "99.00%",
            "ood_fp": "1.39%"
        }
    else:
        # Default: URL (XGBoost)
        metrics = {
            "title": "Evaluasi Model URL: XGBoost Classifier (Produksi)",
            "subtitle": "Model deteksi 17 fitur leksikal dan struktural LegitPhish, dievaluasi pada test-split 20.175 sampel.",
            "precision": "99.94%",
            "recall": "99.98%",
            "f1": "99.96%",
            "accuracy": "99.95%",
            "tp": "12,696",
            "fn": "3",
            "fp": "8",
            "tn": "7,468",
            "ood_title": "Stress-Test OOD OpenPhish Live (300 URL)",
            "ood_acc": "93.00%",
            "ood_fp": "12.96% (HTTPS disparity)"
        }
    
    return render_template("evaluation.html", active="evaluation", metrics=metrics, current_model=model_type)

@app.get("/analysis")
def analysis():
    explanation_data = session.get("last_explanation", {})
    return render_template("analysis.html", active="analysis", data=explanation_data)

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
    Endpoint deteksi Phishing Hybrid (ML + Qwen 2.5 7B via Ollama).
    Mendukung analisis URL (XGBoost) dan analisis Email (Linear SVM).
    """
    data = request.get_json(silent=True) or {}
    input_type = data.get("type", "url")
    target_input = (data.get("url") or data.get("text") or "").strip()

    if not target_input:
        return jsonify({"error": "Target analisis (URL atau teks email) tidak boleh kosong"}), 400

    # 1. Inferensi Detektor Pertama (Machine Learning)
    if input_type == "email" or len(target_input.split()) > 4 and not target_input.startswith(("http://", "https://", "www.")):
        ml_res = ml_engine.predict_email_ml(target_input)
    else:
        ml_res = ml_engine.predict_url_ml(target_input)

    # 2. Pemeriksa Kedua Independen (Qwen 2.5 7B via Ollama)
    qwen_res = ml_engine.get_qwen_verification(target_input, ml_res["type"], ml_res)

    # 3. Rekonsiliasi & Gabungan Hasil
    combined_result = {
        "url": target_input,
        "input_type": ml_res["type"],
        "prediction": ml_res["prediction"],
        "confidence": ml_res["confidence"],
        "prob_phish": ml_res["prob_phish"],
        "model_name": ml_res["model_name"],
        "features": ml_res["features"],
        "recommendation": ml_res["recommendation"],
        "qwen": qwen_res,
        "agreement": qwen_res["agreement"],
        "status_text": qwen_res["status_text"]
    }

    # Simpan ke sesi untuk halaman /analysis
    session["last_explanation"] = {
        "input": target_input,
        "type": ml_res["type"],
        "ml_result": ml_res,
        "qwen_result": qwen_res
    }

    # Simpan ke daftar riwayat scan sesi
    history_list = session.get("scan_history", [])
    now_str = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    history_list.insert(0, {
        "url": target_input[:80] + ("..." if len(target_input) > 80 else ""),
        "type": ml_res["type"].upper(),
        "time": now_str,
        "prediction": ml_res["prediction"],
        "confidence": ml_res["confidence"],
        "model": ml_res["model_name"].split()[0],
        "qwen_status": qwen_res["status_text"]
    })
    session["scan_history"] = history_list[:30]

    return jsonify(combined_result)

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", os.environ.get("PORT", 5000)))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print("=" * 60)
    print(f"  PhisGuard Dual-Engine berjalan di: http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(debug=debug, host="0.0.0.0", port=port)
