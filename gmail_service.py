import os
import json
import base64
import re
from pathlib import Path
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
    """Mengambil Google Client ID & Secret dari Environment Variable atau config.json."""
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

def get_authorization_url(redirect_uri, state=None):
    """Menghasilkan URL login resmi Google OAuth 2.0 dengan proteksi state CSRF."""
    client_config = get_client_config(redirect_uri)
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    if state:
        flow.state = state
    auth_url, generated_state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    return auth_url, generated_state

def exchange_code_for_token_dict(code, redirect_uri, state=None):
    """Menukarkan auth code dari Google dengan OAuth 2.0 credentials dict."""
    client_config = get_client_config(redirect_uri)
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
        state=state
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

def list_inbox_messages(creds_dict, max_results=8):
    """Mengambil daftar ringkas email terbaru dari Inbox pengguna."""
    try:
        creds = get_credentials_from_dict(creds_dict)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        
        # Ambil daftar ID pesan di INBOX
        res = service.users().messages().list(userId="me", maxResults=max_results, q="in:inbox").execute()
        messages_meta = res.get("messages", [])
        
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
            
            # Format tanggal sederhana jika memungkinkan
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
        return emails
    except Exception as e:
        print(f"[GMAIL] Error listing messages: {e}")
        return []

def _extract_body_and_links(payload):
    """Mengekstrak plain text, HTML, dan hyperlink dari payload pesan MIME Gmail."""
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
    
    # Kumpulkan seluruh tautan/links yang ditemukan (baik di plain text maupun tag <a href>)
    embedded_urls = []
    
    if html_text:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://")) and href not in embedded_urls:
                    embedded_urls.append(href)
            # Jika plain text kosong, ambil teks dari HTML
            if not body_text:
                body_text = soup.get_text(separator="\n", strip=True)
        except Exception:
            pass

    # Ekstrak URL via Regex jika masih ada tautan mentah di body text
    url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    for raw_url in url_regex.findall(body_text):
        clean_u = raw_url.strip().rstrip(".,;!)]")
        if clean_u not in embedded_urls:
            embedded_urls.append(clean_u)
            
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
        
        # Format gabungan siap saji ke Scanner
        lines = [
            f"Subjek: {subject}",
            f"Pengirim: {sender}",
            f"Waktu: {date}",
            "",
            "Isi Pesan:",
            cleaned_body
        ]
        
        if urls:
            lines.append("")
            lines.append("Tautan Terdeteksi di Pesan:")
            for u in urls[:5]:
                lines.append(f"- {u}")
                
        formatted_content = "\n".join(lines)
        return {
            "success": True,
            "subject": subject,
            "sender": sender,
            "date": date,
            "body": cleaned_body,
            "urls": urls,
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
