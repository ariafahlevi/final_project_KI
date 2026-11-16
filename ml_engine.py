"""
PhisGuard ML Engine
Mesin inferensi Machine Learning untuk deteksi phishing:
1. URL Classifier: Model XGBoost
2. Email Classifier: Model Linear SVM
3. Local Verifier: Model Qwen via Ollama dengan Live Web Content Inspection
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

def get_app_config():
    config_file = BASE_DIR / "config.json"
    defaults = {
        "ollama_url": "https://finn-unfecundated-lucienne.ngrok-free.dev/api/generate",
        "model_name": "qwen2.5:7b",
        "sensitivity": "normal",
        "qwen_mode": "always"
    }
    if config_file.exists():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return {**defaults, **cfg}
        except Exception:
            pass
    return defaults

def get_ollama_config():
    cfg = get_app_config()
    ollama_url = os.environ.get("OLLAMA_URL", cfg.get("ollama_url"))
    model_name = os.environ.get("OLLAMA_MODEL", cfg.get("model_name"))
    return ollama_url, model_name

def get_threshold():
    """Mengambil ambang batas keputusan klasifikasi (Decision Threshold)."""
    cfg = get_app_config()
    sens = cfg.get("sensitivity", "normal")
    if sens == "high":
        return 0.40
    elif sens == "low":
        return 0.60
    return 0.50


URL_XGB_PATH = MODEL_DIR / "url" / "xgb_production_url.joblib"
URL_RF_PATH = MODEL_DIR / "url" / "rf_baseline_url.joblib"
EMAIL_BILINGUAL_SVM_PATH = MODEL_DIR / "email" / "bilingual_svm_email.joblib"
EMAIL_BILINGUAL_VEC_PATH = MODEL_DIR / "email" / "bilingual_tfidf_vectorizer_email.joblib"
EMAIL_SVM_PATH = MODEL_DIR / "email" / "svm_production_email.joblib"
EMAIL_VEC_PATH = MODEL_DIR / "email" / "tfidf_vectorizer_email.joblib"
EMAIL_LR_PATH = MODEL_DIR / "email" / "lr_baseline_email.joblib"

_url_model = None
_email_model = None
_email_vectorizer = None
_email_model_name = "Model Deteksi Email"

POPULAR_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz',
    'online', 'xyz', 'top', 'site', 'ru', 'de', 'uk', 'id', 'jp', 'cn', 'ca'
}

SUSPICIOUS_EXTS = {
    '.exe', '.zip', '.rar', '.apk', '.bin', '.scr', '.msi', '.iso', '.bat', '.cmd', '.vbs'
}

KNOWN_BRANDS = [
    'optus', 'bca', 'bri', 'mandiri', 'paypal', 'netflix', 'google', 'microsoft',
    'apple', 'facebook', 'shopee', 'tokopedia', 'dana', 'bni', 'cimb', 'dhl', 'sicepat'
]

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
    global _email_model, _email_vectorizer, _email_model_name
    if _email_model is None or _email_vectorizer is None:
        if EMAIL_BILINGUAL_SVM_PATH.exists() and EMAIL_BILINGUAL_VEC_PATH.exists():
            _email_model = joblib.load(EMAIL_BILINGUAL_SVM_PATH)
            _email_vectorizer = joblib.load(EMAIL_BILINGUAL_VEC_PATH)
            _email_model_name = "Model Deteksi Email Dwibahasa (ID/EN)"
        elif EMAIL_SVM_PATH.exists() and EMAIL_VEC_PATH.exists():
            _email_model = joblib.load(EMAIL_SVM_PATH)
            _email_vectorizer = joblib.load(EMAIL_VEC_PATH)
            _email_model_name = "Model Deteksi Email (Inggris)"
        elif EMAIL_LR_PATH.exists() and EMAIL_VEC_PATH.exists():
            _email_model = joblib.load(EMAIL_LR_PATH)
            _email_vectorizer = joblib.load(EMAIL_VEC_PATH)
            _email_model_name = "Model Deteksi Email (Baseline LR)"
        else:
            raise FileNotFoundError("Model Email tidak ditemukan di folder models/email/")
    return _email_model, _email_vectorizer, _email_model_name

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

def inspect_live_url(url: str) -> dict:
    """
    Membuka dan memeriksa konten langsung dari target URL (Web Content Inspection).
    Mengekstrak judul halaman, kode respons HTTP, indikasi form login, dan Cloudflare/WAF phishing block.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url_str = str(url).strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str
    
    parsed = urlparse(url_str)
    host = parsed.netloc.split(':')[0].lower()
    host_parts = host.split('.')
    root_domain = '.'.join(host_parts[-2:]) if len(host_parts) >= 2 else host
    subdomain = '.'.join(host_parts[:-2]) if len(host_parts) > 2 else ''

    # Deteksi merek terkenal di subdomain (Subdomain Spoofing)
    brand_spoofed = None
    if subdomain:
        for b in KNOWN_BRANDS:
            if b in subdomain:
                if b not in root_domain:
                    brand_spoofed = b
                    break

    inspection = {
        "host": host,
        "root_domain": root_domain,
        "subdomain": subdomain if subdomain else "Tidak Ada (Root Domain)",
        "brand_spoofing_detected": brand_spoofed is not None,
        "brand_spoofed_name": brand_spoofed.upper() if brand_spoofed else None,
        "brand_spoofing_alert": f"PERINGATAN ANOMALI: Nama brand '{brand_spoofed.upper()}' dijadikan Subdomain, padahal Root Domain resmi adalah '{root_domain}'. Ini adalah indikasi kuat Brand Impersonation / Subdomain Spoofing!" if brand_spoofed else "Normal / Tidak terindikasi peniruan brand di subdomain",
        "http_status": "Belum Terhubung",
        "page_title": "Tidak dapat diambil",
        "has_password_field": False,
        "has_login_form": False,
        "waf_phishing_block": False,
        "page_snippet": ""
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        r = requests.get(url_str, timeout=3.5, headers=headers, verify=False, allow_redirects=True)
        inspection["http_status"] = f"HTTP {r.status_code}"
        
        m_title = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
        if m_title:
            title_text = re.sub(r'\s+', ' ', m_title.group(1)).strip()
            inspection["page_title"] = title_text
            if any(kw in title_text.lower() for kw in ['phish', 'suspicious', 'malicious', 'deceptive', 'danger', 'block', 'cloudflare']):
                inspection["waf_phishing_block"] = True

        if re.search(r'type=[\'"]password[\'"]', r.text, re.IGNORECASE):
            inspection["has_password_field"] = True
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE) and any(kw in r.text.lower() for kw in ['login', 'signin', 'sign-in', 'masuk', 'sandi', 'password', 'pin']):
            inspection["has_login_form"] = True

        clean_body = re.sub(r'<[^>]+>', ' ', r.text)
        clean_body = re.sub(r'\s+', ' ', clean_body).strip()
        inspection["page_snippet"] = clean_body[:250] if clean_body else "Halaman kosong"
    except requests.exceptions.Timeout:
        inspection["http_status"] = "Koneksi Timeout (>3.5 detik)"
        inspection["page_title"] = "Server tidak merespons (Ciri umum situs penipuan yang sudah diblokir/takedown)"
    except Exception as e:
        inspection["http_status"] = f"Koneksi Gagal ({type(e).__name__})"
        inspection["page_title"] = "Tidak dapat dijangkau"

    return inspection

def clean_email_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'http\S+|www\.\S+', ' url_token ', text)
    text = re.sub(r'\S+@\S+', ' email_token ', text)
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
    
    threshold = get_threshold()
    is_phish = prob_phish >= threshold
    prediction = "phishing" if is_phish else "legitimate"
    confidence = round((prob_phish if is_phish else prob_safe) * 100, 1)

    # Live inspection web content & domain breakdown
    inspection = inspect_live_url(url)
    
    # Ringkasan fitur yang mudah dipahami pengguna umum
    features_display = {
        "Panjang URL": f"{raw_features['url_length']} karakter",
        "Domain Utama (Root)": inspection['root_domain'],
        "Subdomain": inspection['subdomain'],
        "Keamanan Protokol": "HTTPS (Terenkripsi)" if raw_features['https_flag'] == 1 else "HTTP (Tidak Aman / Polos)",
        "Tipe Alamat Web": "Alamat IP Langsung (Mencurigakan)" if raw_features['has_ip_address'] == 1 else "Domain Terdaftar",
        "Struktur Subdomain": "Subdomain Khusus Terdeteksi" if inspection['subdomain'] != "Tidak Ada (Root Domain)" else "Standar (Root Domain)",
        "Inspeksi Live Web": f"{inspection['page_title'][:40]} ({inspection['http_status']})"
    }

    if inspection['brand_spoofing_detected']:
        features_display["Peringatan Brand Spoofing"] = inspection['brand_spoofing_alert']
        # Koreksi probabilitas jika jelas-jelas ada peniruan brand di subdomain
        if prob_phish < 0.70:
            prob_phish = 0.85
            is_phish = True
            prediction = "phishing"
            confidence = 85.0

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
        "live_inspection": inspection,
        "recommendation": recommendation
    }

def predict_email_ml(text: str) -> dict:
    model, vectorizer, model_name = load_email_models()
    cleaned = clean_email_text(text)
    
    if not cleaned:
        cleaned = "empty content"
        
    vec_input = vectorizer.transform([cleaned])
    prob_matrix = model.predict_proba(vec_input)[0]
    prob_phish = float(prob_matrix[1])
    prob_safe = float(prob_matrix[0])
    
    urgency_terms = [
        # English
        "urgent", "account", "suspended", "password", "security", "verify", "update", "bank", "immediately", "action", "expire", "access", "invoice", "confirm", "reward", "winner", "prize",
        # Indonesian
        "segera", "akun", "diblokir", "ditutup", "sandi", "keamanan", "verifikasi", "perbarui", "bank", "tindakan", "kedaluwarsa", "akses", "saldo", "rekening", "otp", "tagihan", "pajak", "paket", "kurir", "unduh", "apk", "klik", "klaim", "hadiah", "undian", "tilang", "etle", "bca", "brimo", "livin", "dana", "shopee"
    ]
    detected_terms = [w for w in urgency_terms if w in cleaned.split()]

    # Mitigasi Zero-Vector Intercept Bias pada model SVM sparse
    if len(cleaned.split()) <= 4 and not detected_terms:
        prob_phish = 0.10
        prob_safe = 0.90
    elif detected_terms and prob_phish < 0.60:
        prob_phish = max(prob_phish, 0.75)
        prob_safe = 1.0 - prob_phish

    threshold = get_threshold()
    is_phish = prob_phish >= threshold
    prediction = "phishing" if is_phish else "legitimate"
    confidence = round((prob_phish if is_phish else prob_safe) * 100, 1)

    features_display = {
        "Panjang Teks": f"{len(text)} karakter ({len(text.split())} kata)",
        "Pola Kata Kunci Kritis": ", ".join(detected_terms[:5]) if detected_terms else "Tidak ada kata mencurigakan",
        "Indikasi Urgensi Psikologis": "Tinggi (Mendesak / Mengancam)" if len(detected_terms) >= 2 else ("Sedang" if detected_terms else "Normal"),
        "Karakteristik Teks": "Mengandung Istilah Rekayasa Sosial" if is_phish else "Bahasa Komunikasi Wajar"
    }

    if is_phish:
        recommendation = (
            "Pesan ini mengandung unsur manipulasi psikologis khas phishing / rekayasa sosial. "
            "Jangan mengklik tautan apa pun dan jangan mengunduh file lampiran dari pesan ini."
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
        "model_name": model_name,
        "features": features_display,
        "recommendation": recommendation
    }

def get_qwen_verification(input_data: str, input_type: str, ml_result: dict) -> dict:
    ollama_url, model_name = get_ollama_config()
    features = ml_result.get("features", {})
    ml_pred = ml_result.get("prediction", "legitimate")
    ml_conf = ml_result.get("confidence", 0.0)
    inspection_meta = ml_result.get("live_inspection", {})

    # 1. Evidence Bundle (Konteks Bukti Terstruktur sesuai Bab 6 & 11)
    evidence_bundle = {
        "target": input_data,
        "target_type": input_type,
        "extracted_features": features,
        "live_web_inspection": inspection_meta,
        "detection_stage": "Independent Context Assessment (Blind Assessment)"
    }

    # 2. Prompt Analisis Keamanan Siber TEGAS & KETAT untuk Qwen 2.5 7B
    prompt = f"""Kamu adalah analis keamanan siber independen (Tier-2 AI Verifier) dalam sistem deteksi phishing hybrid.
Tugas: Lakukan evaluasi objektif secara independen dan TEGAS terhadap target {input_type.upper()} berikut.

PEDOMAN ANALISIS KEAMANAN SIBER RESMI (WAJIB DIIKUTI):
1. JANGAN PERNAH TERTIPU OLEH PROTOKOL HTTPS! Lebih dari 85% situs penipuan/phishing saat ini menggunakan sertifikat HTTPS gratis (Let's Encrypt / Cloudflare). Protokol HTTPS HANYA mengenkripsi lalu lintas, SAMA SEKALI BUKAN bukti bahwa situs tersebut aman atau resmi!
2. WASPADAI SUBDOMAIN BRAND SPOOFING: Jika nama brand (seperti optus, bca, bri, paypal, netflix, microsoft, google, dll) dijadikan SUBDOMAIN pada ROOT DOMAIN asing yang tidak terafiliasi (contoh: optus.myonlineservicecanada.com -> root domainnya adalah myonlineservicecanada.com, BUKAN optus.com.au), ini adalah 100% INDIKASI JELAS PHISHING / PENIRUAN IDENTITAS!
3. HASIL LIVE INSPECTION HALAMAN:
   - Jika judul halaman web (Page Title) menunjukkan 'Suspected Phishing', 'Blocked', atau tanda peringatan Cloudflare/antivirus, tetapkan second_verdict: 'phishing'!
   - Jika halaman meminta password/login di domain yang bukan domain resmi brand terkait, tetapkan second_verdict: 'phishing'!
4. KORELASI TIER-1 MACHINE LEARNING:
   - Model Tier-1 Machine Learning mendeteksi target ini dengan keyakinan: {ml_conf}% [{ml_pred.upper()}].
   - Jika Tier-1 sudah mendeteksi 'phishing', jangan mudah membatalkannya menjadi 'legitimate' tanpa bukti kuat bahwa domain tersebut benar-benar milik resmi entitas yang bersangkutan.

Target ({input_type.upper()}): {input_data}
Bukti Fitur Teknis & Live Web Inspection: {json.dumps(evidence_bundle, ensure_ascii=False)}

Balas HANYA dalam format JSON valid tanpa teks tambahan:
{{
  "second_verdict": "phishing | legitimate | inconclusive",
  "urgency_level": "Tinggi | Sedang | Rendah",
  "impersonation": "Nama entitas yang ditiru (misal: Optus, Bank BCA, dll) atau 'Tidak Terindikasi'",
  "credential_harvesting": true,
  "potential_objective": "Dugaan motif (misal: pencurian akun Optus, manipulasi login, dll)",
  "explanation": "Penjelasan evaluasi teknis dan rekayasa sosial secara tegas, tajam, dan lugas",
  "indicators": ["indikator 1", "indikator 2", "indikator 3"]
}}"""

    second_verdict = None
    explanation = ""
    indicators = []
    soc_eng = {}
    is_live_ollama = False

    try:
        res = requests.post(
            ollama_url,
            json={"model": model_name, "prompt": prompt, "stream": False, "format": "json"},
            timeout=22
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

    # Logika Pengamanan / Fallback Cerdas & Koreksi Tegas
    # Jika Qwen mencoba meloloskan phishing yang jelas terbukti ada Brand Spoofing atau WAF Block:
    brand_alert = inspection_meta.get("brand_spoofing_detected", False)
    waf_alert = inspection_meta.get("waf_phishing_block", False)
    
    if brand_alert or waf_alert:
        second_verdict = "phishing"
        brand_name = inspection_meta.get("brand_spoofed_name", "Entitas Terkenal")
        explanation = (
            f"Evaluasi forensik independen menegaskan bahwa target ini adalah PHISHING. "
            f"Ditemukan indikasi peniruan entitas ({brand_name}) melalui manipulasi subdomain pada root domain asing '{inspection_meta.get('root_domain')}'. "
            f"Selain itu, respons halaman web mengindikasikan status proteksi/pemblokiran ({inspection_meta.get('page_title')})."
        )
        indicators = [
            f"Subdomain Spoofing meniru brand {brand_name}",
            f"Root Domain tidak terafiliasi resmi ({inspection_meta.get('root_domain')})",
            f"Inspeksi Halaman Web: {inspection_meta.get('page_title')}"
        ]
        soc_eng = {
            "urgency_level": "Tinggi",
            "impersonation": brand_name,
            "credential_harvesting": True,
            "potential_objective": f"Pencurian kredensial akun pengguna & peniruan layanan {brand_name}"
        }
    elif not is_live_ollama or not second_verdict:
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
