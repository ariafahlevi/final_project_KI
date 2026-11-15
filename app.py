import os
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import ml_engine
import pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phisguard-security-key-2026")

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
    model_type = request.args.get("model", "url")
    
    if model_type == "email":
        metrics = {
            "title": "Evaluasi Deteksi Email",
            "subtitle": "Hasil pengujian sistem terhadap ribuan sampel pesan email phishing dan email kerja normal.",
            "precision": "98.6%",
            "recall": "98.6%",
            "f1": "98.6%",
            "accuracy": "99.0%",
            "tp": "1.296",
            "fn": "18",
            "fp": "18",
            "tn": "2.170",
            "ood_title": "Uji Coba Email Kantor Nyata (600 Email)",
            "ood_acc": "99.0%",
            "ood_fp": "1.4%"
        }
    else:
        metrics = {
            "title": "Evaluasi Deteksi URL",
            "subtitle": "Hasil pengujian sistem terhadap ribuan sampel tautan berbahaya dan tautan website resmi.",
            "precision": "99.9%",
            "recall": "100.0%",
            "f1": "100.0%",
            "accuracy": "99.9%",
            "tp": "12.696",
            "fn": "3",
            "fp": "8",
            "tn": "7.468",
            "ood_title": "Uji Coba Tautan Aktif di Internet (300 Tautan)",
            "ood_acc": "93.0%",
            "ood_fp": "7.0%"
        }
    
    return render_template("evaluation.html", active="evaluation", metrics=metrics, current_model=model_type)

@app.get("/analysis")
def analysis():
    explanation_data = session.get("last_explanation", {})
    return render_template("analysis.html", active="analysis", data=explanation_data)

@app.get("/settings")
def settings():
    ollama_url, model_name = ml_engine.get_ollama_config()
    saved = request.args.get("saved") == "1"
    return render_template("settings.html", active="settings", ollama_url=ollama_url, model_name=model_name, saved=saved)

@app.post("/settings/ollama")
def save_ollama_settings():
    new_url = request.form.get("ollama_url", "").strip()
    if new_url:
        if not new_url.endswith("/api/generate"):
            new_url = new_url.rstrip("/") + "/api/generate"
        import json
        from pathlib import Path
        config_path = Path(__file__).resolve().parent / "config.json"
        cfg = {"ollama_url": new_url, "model_name": "qwen2.5:7b"}
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    return redirect(url_for("settings", saved="1"))

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

@app.get("/report/pdf")
def download_pdf_report():
    """Mengunduh Laporan Investigasi Keamanan Resmi dalam format PDF."""
    result = session.get("last_result")
    if not result:
        return redirect(url_for("scanner"))
    
    pdf_buffer = pdf_report.generate_pdf_report(result)
    analysis_id = result.get("analysis_id", "report")
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Laporan_PhisGuard_{analysis_id}.pdf"
    )

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

    history_list = session.get("scan_history", [])
    now_str = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    history_list.insert(0, {
        "analysis_id": analysis_id,
        "url": target_input[:80] + ("..." if len(target_input) > 80 else ""),
        "type": "URL" if ml_res["type"] == "url" else "EMAIL",
        "time": now_str,
        "prediction": ml_res["prediction"],
        "confidence": ml_res["confidence"],
        "model": ml_res["model_name"],
        "qwen_status": qwen_res["status_text"]
    })
    session["scan_history"] = history_list[:30]

    return jsonify(combined_result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"PhisGuard berjalan di: http://127.0.0.1:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
