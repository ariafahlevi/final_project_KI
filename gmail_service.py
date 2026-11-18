import os
import json
import base64
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

def get_google_config():
    """Mengambil Google Client ID & Secret dari Environment Variable (.env) atau config.json."""
    # Selalu muat ulang dari file .env secara dinamis
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=True)

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    
    if (not client_id or not client_secret) and CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                client_id = client_id or data.get("google_client_id", "").strip()
                client_secret = client_secret or data.get("google_client_secret", "").strip()
        except Exception:
            pass
            
    return client_id, client_secret

def is_google_configured():
    client_id, client_secret = get_google_config()
    return bool(client_id and client_secret)

def get_client_config(redirect_uri):
    client_id, client_secret = get_google_config()
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri]
        }
    }

def get_authorization_url(redirect_uri, state=None, prompt="select_account consent"):
    """Menghasilkan URL login resmi Google OAuth 2.0 dengan proteksi state CSRF."""
    client_config = get_client_config(redirect_uri)
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
        autogenerate_code_verifier=False
    )
    auth_kwargs = {
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": prompt
    }
    if state:
        auth_kwargs["state"] = state

    auth_url, generated_state = flow.authorization_url(**auth_kwargs)
    return auth_url, generated_state

def exchange_code_for_token_dict(code, redirect_uri, state=None):
    """Menukarkan auth code dari Google dengan OAuth 2.0 credentials dict."""
    client_config = get_client_config(redirect_uri)
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
        state=state,
        autogenerate_code_verifier=False
    )
    flow.fetch_token(code=code)
    creds = flow.credentials
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }

def get_credentials_from_dict(creds_dict):
    return Credentials(
        token=creds_dict.get("token"),
        refresh_token=creds_dict.get("refresh_token"),
        token_uri=creds_dict.get("token_uri"),
        client_id=creds_dict.get("client_id"),
        client_secret=creds_dict.get("client_secret"),
        scopes=creds_dict.get("scopes")
    )

def get_user_email(creds_dict):
    """Mengambil alamat email pengguna yang sedang login."""
    try:
        creds = get_credentials_from_dict(creds_dict)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress", "Akun Google Terhubung")
    except Exception as e:
        print(f"[GMAIL] Failed to get user profile: {e}")
        return "Pengguna Gmail"

def _clean_and_unwrap_url(raw_url: str) -> str:
    """
    Membersihkan URL dari noise tracking parameter dan unwrap redirect wrappers
    (Customer.io, Netcore, Sendgrid, Mailchimp, dsb).
    """
    if not raw_url:
        return ""
        
    # Gabungkan baris yang terputus spasi/newline dalam URL
    clean_url = re.sub(r'[\r\n\t]', '', str(raw_url)).strip().rstrip(".,;!)]")
    clean_url = re.sub(r'([?&=])\s+', r'\1', clean_url)
    
    # 1. Unwrap base64 redirect wrappers (Customer.io email.<domain>/e/c/<base64>)
    try:
        if "/e/c/" in clean_url:
            token_part = clean_url.split("/e/c/")[1].split("/")[0]
            rem = len(token_part) % 4
            if rem > 0:
                token_part += "=" * (4 - rem)
            dec = base64.urlsafe_b64decode(token_part.encode("ascii")).decode("utf-8", errors="ignore")
            parsed_json = json.loads(dec)
            if "href" in parsed_json and parsed_json["href"].startswith(("http://", "https://")):
                clean_url = parsed_json["href"]
    except Exception:
        pass

    # 2. Unwrap direct parameter redirects (?url=, ?redirect_to=, ?dest=, ?target=)
    try:
        p_temp = urlparse(clean_url)
        if p_temp.query:
            qs_temp = parse_qs(p_temp.query)
            for target_param in ["redirect_to", "dest", "destination", "url", "redirect", "target", "href", "link", "r"]:
                if target_param in qs_temp and qs_temp[target_param]:
                    val = qs_temp[target_param][0]
                    if val.startswith(("http://", "https://")):
                        return _clean_and_unwrap_url(val)
    except Exception:
        pass

    # 3. Handle Netcore tracking redirect (/vtrack or trk.*)
    try:
        p_check = urlparse(clean_url)
        host_low = p_check.netloc.lower().split(":")[0]
        path_low = p_check.path.lower()
        if "/vtrack" in path_low or host_low.startswith("trk."):
            # Ekstrak root domain platform (contoh: trk.nc.kitabisa.com -> kitabisa.com)
            parts = host_low.split(".")
            if len(parts) >= 2:
                if len(parts) >= 3 and parts[-2] in ["co", "com", "ac", "go", "or", "net", "edu"]:
                    root_d = ".".join(parts[-3:])
                else:
                    root_d = ".".join(parts[-2:])
                return f"https://{root_d}"
    except Exception:
        pass
        
    # 4. Bersihkan query params tracking (utm_*, ajs_*, cio_*, dsb)
    try:
        p = urlparse(clean_url)
        qs = parse_qs(p.query)
        cleaned_qs = {}
        excluded_keys = {
            "mc_cid", "mc_eid", "fbclid", "gclid", "_ga", "_gl", "msclkid",
            "ul", "ml", "sl", "fl", "ext", "pp", "ga", "clientid"
        }
        for k, v in qs.items():
            k_low = k.lower()
            if not (k_low.startswith(("utm_", "ajs_", "cio_", "ref_")) or k_low in excluded_keys):
                cleaned_qs[k] = v
        new_query = urlencode(cleaned_qs, doseq=True)
        clean_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
    except Exception:
        pass
        
    return clean_url

def list_inbox_messages(creds_dict, max_results=30, category="primary", search_query="", page_token=None):
    """Mengambil daftar ringkas email terbaru dari Inbox pengguna dengan filter kategori, pencarian, dan pagination."""
    try:
        creds = get_credentials_from_dict(creds_dict)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        
        # Susun query pencarian Gmail sesuai kategori
        query_parts = ["in:inbox"]
        cat_lower = (category or "").lower().strip()
        if cat_lower in ["primary", "utama"]:
            query_parts.append("category:primary")
        elif cat_lower in ["promotions", "promosi"]:
            query_parts.append("category:promotions")
        elif cat_lower in ["social", "sosial"]:
            query_parts.append("category:social")
        elif cat_lower in ["updates", "update"]:
            query_parts.append("category:updates")
        # Jika category == "all" atau kosong, tidak dibatasi kategori tertentu
        
        if search_query and search_query.strip():
            query_parts.append(search_query.strip())
            
        full_query = " ".join(query_parts)
        
        list_kwargs = {
            "userId": "me",
            "maxResults": min(max(max_results, 5), 50),
            "q": full_query
        }
        if page_token and page_token.strip():
            list_kwargs["pageToken"] = page_token.strip()
            
        # Ambil daftar ID pesan
        res = service.users().messages().list(**list_kwargs).execute()
        messages_meta = res.get("messages", [])
        next_page_token = res.get("nextPageToken", None)
        
        # Fallback jika category:primary menghasilkan 0 (misal Gmail user tidak pakai tab atau semua ada di default)
        if not messages_meta and not page_token and ("category:primary" in full_query) and not search_query:
            res = service.users().messages().list(
                userId="me",
                maxResults=min(max(max_results, 5), 50),
                q="in:inbox"
            ).execute()
            messages_meta = res.get("messages", [])
            next_page_token = res.get("nextPageToken", None)
        
        emails = []
        for m in messages_meta:
            msg_id = m.get("id")
            detail = service.users().messages().get(
                userId="me", id=msg_id, format="metadata",
                metadataHeaders=["Subject", "From", "Date"]
            ).execute()
            
            headers = detail.get("payload", {}).get("headers", [])
            subject = "Tanpa Subjek"
            sender = "Pengirim Tidak Diketahui"
            date = ""
            for h in headers:
                name = h.get("name", "").lower()
                if name == "subject":
                    subject = h.get("value", "Tanpa Subjek")
                elif name == "from":
                    sender = h.get("value", "Pengirim Tidak Diketahui")
                elif name == "date":
                    date = h.get("value", "")
            
            short_date = date.split("+")[0].split("-")[0].strip() if date else ""
            if len(short_date) > 22:
                short_date = short_date[:22]
                
            emails.append({
                "id": msg_id,
                "subject": subject,
                "sender": sender,
                "date": short_date,
                "snippet": detail.get("snippet", "")
            })
        return emails, next_page_token
    except Exception as e:
        print(f"[GMAIL] Error listing messages: {e}")
        return [], None

def _extract_body_and_links(payload):
    """Mengekstrak teks email bersih, mengeliminasi noise markdown, dan mengekstrak hyperlink yang rapi."""
    text_parts = []
    html_parts = []
    
    def walk_parts(part):
        mime_type = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data", "")
        
        if body_data:
            try:
                decoded = base64.urlsafe_b64decode(body_data.encode("ASCII")).decode("utf-8", errors="replace")
                if "text/plain" in mime_type:
                    text_parts.append(decoded)
                elif "text/html" in mime_type:
                    html_parts.append(decoded)
            except Exception:
                pass
                
        parts = part.get("parts", [])
        for subpart in parts:
            walk_parts(subpart)

    walk_parts(payload)
    
    body_text = "\n".join(text_parts).strip()
    html_text = "\n".join(html_parts).strip()
    
    embedded_urls = []
    
    # 1. Ekstrak tautan & teks dari HTML jika tersedia
    if html_text:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for tag in soup(["script", "style", "noscript", "svg", "head"]):
                tag.decompose()
                
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://")):
                    clean_u = _clean_and_unwrap_url(href)
                    if not any(clean_u.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"]):
                        if clean_u not in embedded_urls:
                            embedded_urls.append(clean_u)
                    
                    # Jika teks anchor adalah raw URL tracking yang panjang, rapikan teksnya
                    a_text = a_tag.get_text().strip()
                    if a_text.startswith(("http://", "https://", "trk.", "www.")) or len(a_text) > 60:
                        a_tag.string = clean_u if clean_u else "Tautan Resmi"
                            
            # Jika plain text tidak ada atau banyak noise, gunakan teks dari HTML yang terstruktur
            html_extracted_text = soup.get_text(separator="\n", strip=True)
            if html_extracted_text and (not body_text or len(html_extracted_text) >= len(body_text) * 0.4):
                body_text = html_extracted_text
        except Exception:
            pass

    # 2. Sambungkan baris terputus dalam URL (line-wrapping RFC 2822)
    if body_text:
        body_text = re.sub(r'(https?://[^\s<>]+[=&])\s+([A-Za-z0-9+/=]+)', r'\1\2', body_text)

    # 3. Ekstrak URL via Regex jika masih ada tautan tambahan
    url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    for raw_url in url_regex.findall(body_text):
        clean_u = _clean_and_unwrap_url(raw_url)
        if clean_u and clean_u not in embedded_urls:
            embedded_urls.append(clean_u)

    # 4. Ganti URL tracking panjang di dalam body text dengan root URL bersih
    if body_text:
        def _replace_trk_in_body(m):
            u_found = m.group(0)
            u_c = _clean_and_unwrap_url(u_found)
            return u_c if u_c else u_found

        body_text = re.sub(
            r'https?://[^\s<>"]+(?:vtrack|/e/c/|click|track|\?[A-Za-z0-9_=&%+-]{25,})[^\s<>"]*',
            _replace_trk_in_body,
            body_text
        )

        # 5. Bersihkan noise inline markdown URL seperti "( https://... )" dan sisa hash base64 liar
        body_text = re.sub(r'\(\s*https?://[^\s)]+\s*\)', '', body_text)
        body_text = re.sub(r'!\[.*?\]', '', body_text)
        body_text = re.sub(r'\[(.*?)\]', r'\1', body_text)
        body_text = re.sub(r'\b[A-Za-z0-9+/=]{25,}\b', '', body_text)
        body_text = re.sub(r'[ \t]+', ' ', body_text)
        body_text = re.sub(r'\n{3,}', '\n\n', body_text).strip()
            
    return body_text, embedded_urls

def get_email_full_content(creds_dict, message_id):
    """Mengambil isi lengkap email beserta tautan tersemat dan memformatnya untuk Scanner."""
    try:
        creds = get_credentials_from_dict(creds_dict)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        detail = service.users().messages().get(userId="me", id=message_id, format="full").execute()
        
        headers = detail.get("payload", {}).get("headers", [])
        subject = "Tanpa Subjek"
        sender = "Pengirim Tidak Diketahui"
        date = ""
        for h in headers:
            name = h.get("name", "").lower()
            if name == "subject":
                subject = h.get("value", "Tanpa Subjek")
            elif name == "from":
                sender = h.get("value", "Pengirim Tidak Diketahui")
            elif name == "date":
                date = h.get("value", "")
                
        body_text, urls = _extract_body_and_links(detail.get("payload", {}))
        
        # Bersihkan whitespace berlebih
        cleaned_body = re.sub(r'\n{3,}', '\n\n', body_text).strip()
        if not cleaned_body:
            # Fallback ke snippet jika email tidak memiliki body plain text/html yang dapat diurai
            cleaned_body = (detail.get("snippet") or "").strip()
            if not cleaned_body:
                cleaned_body = "Pesan email ini berisi konten grafis/multimedia atau pemberitahuan tanpa teks panjang."
        
        # Saring URL unik dan relevan (maksimal 5 tautan terpenting tanpa noise duplikasi tracking)
        distinct_urls = []
        seen_normalized = set()
        for u in urls:
            u_clean = _clean_and_unwrap_url(u)
            if u_clean:
                p = urlparse(u_clean)
                norm_key = f"{p.netloc.lower()}{p.path.rstrip('/')}"
                if norm_key not in seen_normalized:
                    seen_normalized.add(norm_key)
                    distinct_urls.append(u_clean)

        # Format gabungan siap saji ke Scanner
        lines = [
            f"Subjek: {subject}",
            f"Pengirim: {sender}",
            f"Waktu: {date}",
            "",
            "Isi Pesan:",
            cleaned_body
        ]
                    
        if distinct_urls:
            lines.append("")
            lines.append("Tautan Terdeteksi di Pesan:")
            for u in distinct_urls[:5]:
                lines.append(f"- {u}")
                
        formatted_content = "\n".join(lines)
        return {
            "success": True,
            "subject": subject,
            "sender": sender,
            "date": date,
            "body": cleaned_body,
            "urls": distinct_urls[:5],
            "formatted_text": formatted_content
        }
    except Exception as e:
        print(f"[GMAIL] Error reading email content: {e}")
        return {
            "success": False,
            "error": str(e),
            "formatted_text": ""
        }

# ==========================================
# MOCK / DEMO DATA (UNTUK PENGUJIAN INSTAN)
# ==========================================
def get_mock_emails():
    """Menyediakan data simulasi inbox Gmail untuk demo instan jika kredensial belum diisi."""
    return [
        {
            "id": "mock-email-01",
            "sender": "BCA Mobile Notification <info@bca-verifikasi-update.com>",
            "subject": "[PENTING] Pemberitahuan Perubahan Tarif Transaksi & Verifikasi Akun",
            "date": "Hari ini, 10:15 WIB",
            "snippet": "Nasabah yang terhormat, terdapat pembaruan tarif transaksi BCA Mobile menjadi Rp 150.000/bulan. Lakukan konfirmasi...",
            "formatted_text": (
                "Subjek: [PENTING] Pemberitahuan Perubahan Tarif Transaksi & Verifikasi Akun\n"
                "Pengirim: BCA Mobile Notification <info@bca-verifikasi-update.com>\n"
                "Waktu: Hari ini, 10:15 WIB\n\n"
                "Isi Pesan:\n"
                "Nasabah Yth, sehubungan dengan peningkatan kualitas layanan, akan diberlakukan tarif baru Rp 150.000/bulan. "
                "Jika Anda tidak menyetujui perubahan tarif ini, segera lakukan konfirmasi verifikasi data rekening Anda "
                "dalam batas waktu 1x24 jam sebelum akun Anda diblokir otomatis.\n\n"
                "Tautan Terdeteksi di Pesan:\n"
                "- https://bca-tarif-konfirmasi.live"
            )
        },
        {
            "id": "mock-email-02",
            "sender": "SiCepat Express Customer Care <kurir@sicepat-resi-verifikasi.xyz>",
            "subject": "Paket Anda Tertahan - Konfirmasi Pengantaran Alamat",
            "date": "Kemarin, 16:40 WIB",
            "snippet": "Paket SiCepat Express gagal dikirimkan karena nomor rumah tidak lengkap. Unduh file resi konfirmasi alamat paket apk...",
            "formatted_text": (
                "Subjek: Paket Anda Tertahan - Konfirmasi Pengantaran Alamat\n"
                "Pengirim: SiCepat Express Customer Care <kurir@sicepat-resi-verifikasi.xyz>\n"
                "Waktu: Kemarin, 16:40 WIB\n\n"
                "Isi Pesan:\n"
                "Paket SiCepat Express gagal dikirimkan karena alamat tidak ditemukan kurir. "
                "Unduh file resi konfirmasi alamat paket apk untuk pengantaran ulang kurir besok pagi.\n\n"
                "Tautan Terdeteksi di Pesan:\n"
                "- http://sicepat-tracking-resi.xyz/unduh/resi-paket.apk"
            )
        },
        {
            "id": "mock-email-03",
            "sender": "Divisi Engineering <engineering@kantor.co.id>",
            "subject": "Sinkronisasi Sprint Review & Evaluasi Rilis v2.4",
            "date": "16 Nov 2026, 09:00 WIB",
            "snippet": "Selamat pagi tim, mohon kirimkan update progress sprint review dan kendala blocking sebelum jam 5 sore untuk standup...",
            "formatted_text": (
                "Subjek: Sinkronisasi Sprint Review & Evaluasi Rilis v2.4\n"
                "Pengirim: Divisi Engineering <engineering@kantor.co.id>\n"
                "Waktu: 16 Nov 2026, 09:00 WIB\n\n"
                "Isi Pesan:\n"
                "Selamat pagi tim, mohon kirimkan update progress sprint review dan kendala blocking sebelum jam 5 sore untuk standup harian. "
                "Catatan release notes sudah dirangkum di wiki internal. Terima kasih atas kerja samanya."
            )
        }
    ]
