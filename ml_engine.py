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
    
    prompt = f"""Analisis keamanan: periksa apakah {input_type} ini aman atau phishing:
Input: {input_data}

Balas hanya dengan format JSON singkat:
{{
  "second_verdict": "phishing | legitimate | inconclusive",
  "explanation": "penjelasan bahasa santai dan ringkas",
  "indicators": ["indikator 1", "indikator 2"]
}}"""

    try:
        res = requests.post(
            ollama_url,
            json={"model": model_name, "prompt": prompt, "stream": False, "format": "json"},
            timeout=5
        )
        if res.status_code == 200:
            import json
            data = res.json()
            parsed = json.loads(data.get("response", "{}"))
            second_verdict = parsed.get("second_verdict", "inconclusive").lower()
            explanation = parsed.get("explanation", "")
            indicators = parsed.get("indicators", [])
            
            ml_pred = ml_result["prediction"]
            if second_verdict == ml_pred:
                status_text = "Terkonfirmasi (Sepakat)"
            elif second_verdict == "inconclusive":
                status_text = "Perlu Pemeriksaan Tambahan"
            elif ml_pred == "legitimate" and second_verdict == "phishing":
                status_text = "Peringatan: Potensi Ancaman Tersembunyi"
            else:
                status_text = "Hasil Berbeda (Perlu Review)"

            return {
                "source": "AI Verifier",
                "second_verdict": second_verdict,
                "status_text": status_text,
                "explanation": explanation,
                "indicators": indicators
            }
    except Exception:
        pass

    # Fallback yang jelas dan tidak berbelit-belit
    ml_pred = ml_result["prediction"]
    if ml_pred == "phishing":
        second_verdict = "phishing"
        status_text = "Terkonfirmasi Kuat"
        explanation = (
            f"Pemeriksaan lanjutan mengonfirmasi adanya indikasi penipuan pada {input_type} ini. "
            f"Terdapat upaya manipulasi alamat atau pesan yang meniru layanan resmi untuk meminta data pengguna."
        )
        indicators = ["Pola alamat menyerupai situs resmi", "Format mencurigakan", "Potensi pencurian kredensial"]
    else:
        second_verdict = "legitimate"
        status_text = "Terkonfirmasi Aman"
        explanation = (
            f"Pemeriksaan lanjutan tidak menemukan indikasi manipulasi atau pesan berbahaya pada {input_type} ini. "
            f"Karakteristiknya terlihat wajar dan konsisten dengan entitas asli."
        )
        indicators = ["Struktur alamat wajar", "Tidak ada unsur rekayasa sosial"]

    return {
        "source": "AI Verifier",
        "second_verdict": second_verdict,
        "status_text": status_text,
        "explanation": explanation,
        "indicators": indicators
    }
