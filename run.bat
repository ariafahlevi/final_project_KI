@echo off
title PhishGuard AI
echo ==========================================================
echo           Memulai PhishGuard AI - Web Server
echo ==========================================================
echo.
echo [1/2] Membuka browser ke http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
echo [2/2] Menjalankan server Flask...
echo.
echo Tekan CTRL + C di terminal ini jika ingin mematikan server.
echo.
python app.py
pause
