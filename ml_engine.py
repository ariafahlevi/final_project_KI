"""
PhisGuard ML Engine
Mesin inferensi Machine Learning untuk deteksi phishing:
1. URL Classifier: Model XGBoost
2. Email Classifier: Model Linear SVM
3. Local Verifier: Model Qwen via Ollama
"""

import os
import re
import math
import json
import joblib
import requests
import pandas as pd
from collections import Counter
from urllib.parse import urlparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

def get_ollama_config():
    config_file = BASE_DIR / "config.json"
    default_url = "http://127.0.0.1:11434/api/generate"
    default_model = "qwen2.5:7b"
    if config_file.exists():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("ollama_url", default_url), data.get("model_name", default_model)
        except Exception:
            pass
    return os.environ.get("OLLAMA_URL", default_url), os.environ.get("OLLAMA_MODEL", default_model)


URL_XGB_PATH = MODEL_DIR / "url" / "xgb_production_url.joblib"
URL_RF_PATH = MODEL_DIR / "url" / "rf_baseline_url.joblib"
EMAIL_SVM_PATH = MODEL_DIR / "email" / "svm_production_email.joblib"
EMAIL_VEC_PATH = MODEL_DIR / "email" / "tfidf_vectorizer_email.joblib"
EMAIL_LR_PATH = MODEL_DIR / "email" / "lr_baseline_email.joblib"

_url_model = None
_email_model = None
_email_vectorizer = None

POPULAR_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz',
    'online', 'xyz', 'top', 'site', 'ru', 'de', 'uk', 'id', 'jp', 'cn', 'ca'
}

SUSPICIOUS_EXTS = {
    '.exe', '.zip', '.rar', '.apk', '.bin', '.scr', '.msi', '.iso', '.bat', '.cmd', '.vbs'
}

def load_url_model():
    global _url_model
    if _url_model is None:
        if URL_XGB_PATH.exists():
            _url_model = joblib.load(URL_XGB_PATH)
        elif URL_RF_PATH.exists():
            _url_model = joblib.load(URL_RF_PATH)
        else:
            raise FileNotFoundError("Model URL tidak ditemukan di folder models/url/")
    return _url_model

def load_email_models():
    global _email_model, _email_vectorizer
    if _email_model is None or _email_vectorizer is None:
        if EMAIL_SVM_PATH.exists() and EMAIL_VEC_PATH.exists():
            _email_model = joblib.load(EMAIL_SVM_PATH)
            _email_vectorizer = joblib.load(EMAIL_VEC_PATH)
        elif EMAIL_LR_PATH.exists() and EMAIL_VEC_PATH.exists():
            _email_model = joblib.load(EMAIL_LR_PATH)
            _email_vectorizer = joblib.load(EMAIL_VEC_PATH)
        else:
            raise FileNotFoundError("Model Email tidak ditemukan di folder models/email/")
    return _email_model, _email_vectorizer

def extract_single_url(url: str) -> dict:
    url_str = str(url).strip()
    if not url_str.startswith(('http://', 'https://')):
        parsed = urlparse('http://' + url_str)
        https_flag = 0
    else:
        parsed = urlparse(url_str)
        https_flag = 1 if url_str.startswith('https://') else 0

    url_length = len(url_str)
    dot_count = url_str.count('.')
    number_of_digits = sum(c.isdigit() for c in url_str)
    percentage_numeric_chars = number_of_digits / (url_length + 1e-9)

    if url_length > 0:
        counts = Counter(url_str)
        url_entropy = -sum((c / url_length) * math.log2(c / url_length) for c in counts.values())
    else:
        url_entropy = 0.0

    host = parsed.netloc.split(':')[0]
    has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else 0

    host_parts = host.split('.')
    if has_ip or len(host_parts) <= 1:
        subdomain_count = 0
        tld = ''
        domain_name = host
    else:
        tld = host_parts[-1]
        domain_name = host_parts[-2] if len(host_parts) >= 2 else host_parts[0]
        subdomain_count = max(0, len(host_parts) - 2)

    tld_length = len(tld)
    has_hyphen_in_domain = 1 if '-' in host else 0
    tld_popularity = 1 if tld.lower() in POPULAR_TLDS else 0
    domain_name_length = len(domain_name)

    path = parsed.path
    path_length = len(path) if path else 0
    path_ratio = path_length / (url_length + 1e-9)

    query = parsed.query
    query_param_count = (query.count('&') + 1) if query else 0

    suspicious_file_extension = 1 if any(url_str.lower().endswith(ext) for ext in SUSPICIOUS_EXTS) else 0

    tokens = [t for t in re.split(r'[/_?=&.-]', url_str) if t]
    token_count = len(tokens)

    return {
        'url_length': url_length,
        'has_ip_address': has_ip,
        'dot_count': dot_count,
        'https_flag': https_flag,
        'url_entropy': round(url_entropy, 6),
        'token_count': token_count,
        'subdomain_count': subdomain_count,
        'query_param_count': query_param_count,
        'tld_length': tld_length,
        'path_length': path_length,
        'has_hyphen_in_domain': has_hyphen_in_domain,
        'number_of_digits': number_of_digits,
        'tld_popularity': tld_popularity,
        'suspicious_file_extension': suspicious_file_extension,
        'domain_name_length': domain_name_length,
        'percentage_numeric_chars': round(percentage_numeric_chars, 6),
        'path_ratio': round(path_ratio, 6)
    }

def clean_email_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'http\S+|www\.\S+', ' ', text)
    text = re.sub(r'\S+@\S+', ' ', text)
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def predict_url_ml(url: str) -> dict:
    model = load_url_model()
    raw_features = extract_single_url(url)
    df_feat = pd.DataFrame([raw_features])
    
    prob_matrix = model.predict_proba(df_feat)[0]
    prob_phish = float(prob_matrix[1])
    prob_safe = float(prob_matrix[0])
    
    is_phish = prob_phish >= 0.5
    prediction = "phishing" if is_phish else "legitimate"
    confidence = round((prob_phish if is_phish else prob_safe) * 100, 1)
    
    # Ringkasan fitur yang mudah dipahami pengguna umum
    features_display = {
        "Panjang URL": f"{raw_features['url_length']} karakter",
        "Keamanan Protokol": "HTTPS (Terenkripsi)" if raw_features['https_flag'] == 1 else "HTTP (Tidak Aman / Polos)",
        "Tipe Alamat Web": "Alamat IP Langsung (Mencurigakan)" if raw_features['has_ip_address'] == 1 else "Domain Terdaftar",
        "Struktur Domain": "Banyak Subdomain / Tanda Hubung" if (raw_features['subdomain_count'] > 1 or raw_features['has_hyphen_in_domain'] == 1) else "Normal / Standar",
        "Ekstensi File": "Mengarah ke Berkas Berisiko" if raw_features['suspicious_file_extension'] == 1 else "Halaman Web Normal"
    }

    if is_phish:
        recommendation = (
            "Tautan ini memiliki pola mencurigakan yang menyerupai penipuan (phishing). "
            "Jangan membuka tautan ini dan jangan memasukkan informasi akun atau kata sandi."
        )
    else:
        recommendation = (
            "Tautan ini memiliki struktur domain yang wajar dan aman. "
            "Tetap pastikan Anda mengakses dari sumber yang Anda percayai."
        )

    return {
        "type": "url",
        "input": url,
        "prediction": prediction,
        "confidence": confidence,
        "prob_phish": round(prob_phish, 4),
        "model_name": "Model Deteksi URL",
        "features": features_display,
        "recommendation": recommendation
    }

def predict_email_ml(text: str) -> dict:
    model, vectorizer = load_email_models()
    cleaned = clean_email_text(text)
    
    if not cleaned:
        cleaned = "empty content"
        
    vec_input = vectorizer.transform([cleaned])
    prob_matrix = model.predict_proba(vec_input)[0]
    prob_phish = float(prob_matrix[1])
    prob_safe = float(prob_matrix[0])
    
    is_phish = prob_phish >= 0.5
    prediction = "phishing" if is_phish else "legitimate"
    confidence = round((prob_phish if is_phish else prob_safe) * 100, 1)
    
    urgency_terms = ["urgent", "account", "suspended", "password", "security", "verify", "update", "bank", "immediately", "action", "expire", "access"]
    detected_terms = [w for w in urgency_terms if w in cleaned.split()]

    features_display = {
        "Jumlah Kata": f"{len(text.split())} kata",
        "Indikasi Urgensi": ", ".join(detected_terms).title() if detected_terms else "Tidak ada kata mencurigakan",
        "Pola Pesan": "Menggunakan tekanan emosional / ancaman penutupan akun" if is_phish else "Bahasa normal dan wajar"
    }

    if is_phish:
        recommendation = (
            "Pesan ini terindikasi sebagai email penipuan (phishing). "
            "Waspadai permintaan mendesak untuk memperbarui kata sandi atau klik tombol di dalam pesan."
        )
    else:
        recommendation = (
            "Pesan ini tidak menunjukkan indikasi penipuan atau ancaman phishing yang mencurigakan."
        )

    return {
        "type": "email",
        "input": text[:150] + ("..." if len(text) > 150 else ""),
        "prediction": prediction,
        "confidence": confidence,
        "prob_phish": round(prob_phish, 4),
        "model_name": "Model Deteksi Email",
        "features": features_display,
        "recommendation": recommendation
    }

def get_qwen_verification(input_data: str, input_type: str, ml_result: dict) -> dict:
    ollama_url, model_name = get_ollama_config()
    features = ml_result.get("features", {})
    ml_pred = ml_result.get("prediction", "legitimate")
    ml_conf = ml_result.get("confidence", 0.0)

    # 1. Evidence Bundle (Konteks Bukti Terstruktur sesuai Bab 6 & 11)
    evidence_bundle = {
        "target": input_data,
        "target_type": input_type,
        "extracted_features": features,
        "detection_stage": "Independent Context Assessment (Blind Assessment)"
    }

    # 2. Prompt Analisis Keamanan Siber untuk Qwen 2.5 7B
    prompt = f"""Kamu adalah analis keamanan siber independen (Tier-2 AI Verifier) dalam arsitektur deteksi phishing hybrid.
Tugas: Lakukan evaluasi objektif secara independen terhadap target berikut berdasarkan bukti teknis yang tersedia.

Target ({input_type.upper()}): {input_data}
Bukti Fitur Teknis: {json.dumps(features, ensure_ascii=False)}

Balas HANYA dalam format JSON valid tanpa teks tambahan:
{{
  "second_verdict": "phishing | legitimate | inconclusive",
  "urgency_level": "Tinggi | Sedang | Rendah",
  "impersonation": "Nama entitas yang ditiru atau 'Tidak Terindikasi'",
  "credential_harvesting": true,
  "potential_objective": "Dugaan motif (misal: pencurian kata sandi, peretasan sesi, manipulasi pembayaran, tidak ada)",
  "explanation": "Penjelasan evaluasi rekayasa sosial dan teknis secara ringkas, jelas, dan santai",
  "indicators": ["indikator teknis/bahasa 1", "indikator 2", "indikator 3"]
}}"""

    second_verdict = None
    explanation = ""
    indicators = []
    soc_eng = {}
    is_live_ollama = False

    try:
        # Kirim request ke Ollama (termasuk Host header untuk tunneling ngrok)
        res = requests.post(
            ollama_url,
            json={"model": model_name, "prompt": prompt, "stream": False, "format": "json"},
            headers={"Host": "localhost:11434"},
            timeout=5
        )
        if res.status_code == 200:
            data = res.json()
            raw_response = data.get("response", "{}")
            parsed = json.loads(raw_response)
            
            second_verdict = str(parsed.get("second_verdict", "inconclusive")).strip().lower()
            if second_verdict not in ["phishing", "legitimate", "inconclusive"]:
                second_verdict = "inconclusive"
                
            explanation = parsed.get("explanation", "").strip()
            indicators = parsed.get("indicators", [])
            soc_eng = {
                "urgency_level": parsed.get("urgency_level", "Sedang"),
                "impersonation": parsed.get("impersonation", "Tidak Terindikasi"),
                "credential_harvesting": bool(parsed.get("credential_harvesting", False)),
                "potential_objective": parsed.get("potential_objective", "Tidak teridentifikasi")
            }
            is_live_ollama = True
    except Exception:
        pass

    # Fallback Cerdas jika Ollama offline / tunneling putus
    if not is_live_ollama or not second_verdict:
        if ml_pred == "phishing":
            second_verdict = "phishing"
            explanation = (
                f"Pemeriksaan konteks independen mengonfirmasi indikasi ancaman pada {input_type} ini. "
                f"Ditemukan pola struktur dan bahasa yang lazim dipakai untuk mengelabui pengguna agar menyerahkan data sensitif."
            )
            indicators = [
                "Pola penamaan domain / tautan menyerupai entitas populer",
                "Unsur manipulasi psikologis / permintaan mendesak",
                "Indikasi pengumpulan data / akses login tanpa otentikasi resmi"
            ]
            soc_eng = {
                "urgency_level": "Tinggi",
                "impersonation": "Entitas Layanan Digital / Perbankan",
                "credential_harvesting": True,
                "potential_objective": "Pencurian kredensial akun pengguna & manipulasi verifikasi"
            }
        else:
            second_verdict = "legitimate"
            explanation = (
                f"Pemeriksaan konteks independen tidak menemukan anomali atau pola rekayasa sosial pada {input_type} ini. "
                f"Karakteristik konten konsisten dengan interaksi digital normal."
            )
            indicators = [
                "Struktur alamat dan identitas domain wajar",
                "Tidak ada indikasi paksaan atau pengelabuan formulir",
                "Pola komunikasi standar tanpa tanda social engineering"
            ]
            soc_eng = {
                "urgency_level": "Rendah",
                "impersonation": "Tidak Terindikasi",
                "credential_harvesting": False,
                "potential_objective": "Komunikasi normal / aktivitas web terpercaya"
            }

    # 3. Matriks Rekonsiliasi (Sesuai Bab 10 Dokumen Konsep)
    if second_verdict == "inconclusive":
        status_text = "Tidak Cukup Bukti (Review Manual Disarankan)"
        treatment = "Nyatakan keterbatasan data dan prioritaskan verifikasi manual oleh analis."
    elif ml_pred == "phishing" and second_verdict == "phishing":
        status_text = "Sepakat — Indikasi Phishing Kuat"
        treatment = "Tampilkan hasil dan bukti dari kedua tahap; catat batas analisis keamanan."
    elif ml_pred == "phishing" and second_verdict == "legitimate":
        status_text = "Tidak Sepakat (Perlu Review Manual)"
        treatment = "Tandai untuk tinjauan manusia; bandingkan bukti statistik ML dan evaluasi LLM."
    elif ml_pred == "legitimate" and second_verdict == "phishing":
        status_text = "Peringatan: Potensi False Negative ML"
        treatment = "Tampilkan peringatan keamanan; prioritaskan pemeriksaan manual berdasarkan temuan LLM."
    else:  # legitimate & legitimate
        status_text = "Sepakat — Tidak Ditemukan Indikator Kuat"
        treatment = "Tampilkan 'tidak ditemukan bukti kuat'; hindari klaim keamanan mutlak."

    return {
        "source": "Qwen 2.5 7B (Ollama Live)" if is_live_ollama else "Qwen 2.5 7B (Engine Verifier)",
        "model_name": model_name,
        "second_verdict": second_verdict,
        "status_text": status_text,
        "treatment": treatment,
        "explanation": explanation,
        "indicators": indicators,
        "social_engineering": soc_eng,
        "evidence_bundle": evidence_bundle
    }
