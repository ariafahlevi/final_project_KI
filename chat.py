"""
Script Interaktif Terminal: Chat Langsung dengan Qwen 2.5 7B (Ollama)
Membaca konfigurasi otomatis dari config.json (tersinkronisasi dengan Web UI Pengaturan).
"""
import os
import sys
import json
import time
import requests
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"

def load_config():
    ollama_url = "https://finn-unfecundated-lucienne.ngrok-free.dev/api/generate"
    model_name = "qwen2.5:7b"
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                ollama_url = cfg.get("ollama_url", ollama_url)
                model_name = cfg.get("model_name", model_name)
        except Exception:
            pass
    return ollama_url, model_name

def main():
    ollama_url, model_name = load_config()

    print("=" * 65)
    print("      ROOM CHAT LANGSUNG DENGAN QWEN 2.5 7B (PHISGUARD AI)      ")
    print("=" * 65)
    print(f"Target Server : {ollama_url}")
    print(f"Model         : {model_name}")
    print("Petunjuk      : Ketik pesan seperti biasa lalu tekan Enter.")
    print("                Ketik 'keluar' atau 'exit' untuk selesai.")
    print("-" * 65)

    session_history = []

    # Uji ping awal
    try:
        base_url = ollama_url.replace("/api/generate", "")
        ping_res = requests.get(f"{base_url}/api/tags", timeout=5)
        if ping_res.status_code == 200:
            print("[\u2713] Server Ollama terhubung aktif dan siap digunakan.\n")
        elif ping_res.status_code == 403:
            print("[!] Peringatan: Status 403 Forbidden. Pastikan ngrok teman dijalankan dengan:")
            print("    ngrok http 11434 --host-header=\"localhost:11434\"\n")
    except Exception as e:
        print(f"[!] Server Ollama sedang dicek ({e})...\n")

    while True:
        try:
            user_msg = input("Kamu  : ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSampai jumpa!")
            break

        if not user_msg:
            continue
        if user_msg.lower() in ["keluar", "exit", "quit", "q"]:
            print("Sesi chat selesai. Terima kasih!")
            break

        print("Qwen  : [Sedang berpikir...]", end="\r", flush=True)
        start_time = time.time()

        payload = {
            "model": model_name,
            "prompt": user_msg,
            "stream": False,
            "options": {
                "temperature": 0.4,
                "top_p": 0.9
            }
        }

        try:
            resp = requests.post(
                ollama_url,
                json=payload,
                timeout=35,
                headers={"Content-Type": "application/json"}
            )
            elapsed = time.time() - start_time

            if resp.status_code == 200:
                answer = resp.json().get("response", "").strip()
                print(f"Qwen  : {answer}  ({elapsed:.1f}s)\n")
            elif resp.status_code == 403:
                print(f"Qwen  : [Error 403] Akses ditolak oleh Ollama. Pastikan host tunneling ngrok diizinkan.\n")
            elif resp.status_code == 504:
                print(f"Qwen  : [Error 504] Timeout. Model Qwen sedang memuat bobot ke VRAM atau server sedang sibuk.\n")
            else:
                print(f"Qwen  : [Error {resp.status_code}] Respons server: {resp.text[:150]}\n")

        except requests.exceptions.Timeout:
            print(f"Qwen  : [Error Timeout] Permintaan melebihi 35 detik. Pastikan server Ollama teman tidak overload.\n")
        except requests.exceptions.ConnectionError:
            print(f"Qwen  : [Error Koneksi] Gagal terhubung ke {ollama_url}. Periksa apakah URL ngrok berubah.\n")
        except Exception as ex:
            print(f"Qwen  : [Error Tak Terduga] {ex}\n")

if __name__ == "__main__":
    main()
