#!/usr/bin/env bash
# PhishGuard AI - Linux/macOS Startup Script

echo "=========================================================="
echo "          Memulai PhishGuard AI - Web Server"
echo "=========================================================="
echo ""

# Membuka browser default sesuai sistem operasi
if command -v xdg-open > /dev/null; then
  xdg-open http://127.0.0.1:5000 &
elif command -v open > /dev/null; then
  open http://127.0.0.1:5000 &
fi

echo "Menjalankan Flask server..."
python3 app.py || python app.py
