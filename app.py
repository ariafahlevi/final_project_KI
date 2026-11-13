# Contoh route Flask untuk menjalankan template.
# Salin/merge route ini ke app.py backend kelompok. Jangan mengganti route ML yang sudah ada.
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "ganti-dengan-secret-key"

@app.get("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")

@app.get("/scan")
def scanner():
    return render_template("scanner.html", active="scanner")

@app.get("/history")
def history():
    return render_template("history.html", active="history")

@app.get("/evaluation")
def evaluation():
    # Ganti None dengan metrik evaluasi hasil model aktual.
    return render_template("evaluation.html", active="evaluation", metrics=None)

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
    # Pastikan backend mengirim: prediction ('phishing'/'legitimate'),
    # confidence (angka), features (dict), recommendation (string).
    return render_template("result.html", active="scanner", result=result)

# Implementasikan endpoint POST /api/scan di backend:
# terima JSON {"url": "..."} lalu panggil ekstraksi fitur + CatBoost + Ollama.
# Kembalikan JSON minimal:
# {"url":"...", "prediction":"phishing", "confidence":96.8,
#  "features":{"Panjang URL":45}, "recommendation":"Hindari tautan ini."}

if __name__ == "__main__":
    app.run(debug=True)
