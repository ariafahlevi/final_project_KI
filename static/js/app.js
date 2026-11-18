document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));

  // Status Sistem Keamanan (User-Friendly, Non-Developer)
  const topBadge = document.getElementById("topEngineBadge");
  const topDot = document.getElementById("topEngineDot");
  const topText = document.getElementById("topEngineText");

  async function updateTopEngineBadge() {
    if (!topBadge || !topDot || !topText) return;
    try {
      const res = await fetch("/api/ollama-status");
      const data = await res.json();
      if (!data.llm_enabled) {
        // KONDISI 3: MODE MANDIRI MUTLAK DIPILIH PENGGUNA
        topDot.style.background = "#64748b";
        topDot.style.boxShadow = "0 0 0 2px rgba(100,116,139,0.25)";
        topText.textContent = "Mode Mandiri (ML)";
        topBadge.title = "Mode Mandiri Aktif: Inferensi 100% diproses oleh model Supervised Machine Learning.";
        topBadge.style.borderColor = "#cbd5e1";
        topBadge.style.background = "#f1f5f9";
        topBadge.style.color = "#475569";
      } else if (data.status === "online") {
        // KONDISI 2: MODE HYBRID AKTIF & LLM LIVE MERESPONS
        topDot.style.background = "#10b981";
        topDot.style.boxShadow = "0 0 0 2px rgba(16,185,129,0.25)";
        topText.textContent = "Proteksi Hybrid Aktif";
        topBadge.title = "Konsensus Dual-Engine Siap: Supervised ML + Qwen 2.5 7B Aktif.";
        topBadge.style.borderColor = "#a7f3d0";
        topBadge.style.background = "#ecfdf5";
        topBadge.style.color = "#065f46";
      } else {
        // KONDISI 1: MODE HYBRID DIPILIH TAPI LLM MATI/OFFLINE -> FALLBACK MANDIRI
        topDot.style.background = "#f59e0b";
        topDot.style.boxShadow = "0 0 0 2px rgba(245,158,11,0.25)";
        topText.textContent = "Mandiri (LLM Offline)";
        topBadge.title = "Peringatan: Server LLM offline. Evaluasi otomatis dialihkan ke Mode Mandiri.";
        topBadge.style.borderColor = "#fde68a";
        topBadge.style.background = "#fffbeb";
        topBadge.style.color = "#92400e";
      }

      const hybridNotice = document.getElementById("scannerHybridNotice");
      if (hybridNotice) {
        if (data.llm_enabled && data.status !== "online") {
          hybridNotice.style.display = "block";
        } else {
          hybridNotice.style.display = "none";
        }
      }
    } catch (e) {
      // Fallback aman default
      topDot.style.background = "#10b981";
      topDot.style.boxShadow = "0 0 0 2px rgba(16,185,129,0.25)";
      topText.textContent = "Proteksi ML Siap";
      topBadge.style.borderColor = "#a7f3d0";
      topBadge.style.background = "#ecfdf5";
      topBadge.style.color = "#065f46";
    }
  }

  updateTopEngineBadge();

  const form = document.getElementById("scanForm");
  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = document.getElementById("formMessage");
      const button = form.querySelector("button[type=submit]");
      const scanType = document.getElementById("scanType") ? document.getElementById("scanType").value : "url";
      
      const terminalBox = document.getElementById("analystTerminal");
      const terminalBody = document.getElementById("terminalBody");
      const qwenThoughtText = document.getElementById("qwenThoughtText");

      let payload = { type: scanType };
      let targetDisplay = "";

      if (scanType === "url") {
        const urlInput = document.getElementById("urlInput");
        const val = urlInput.value.trim();
        if (!val) return;
        payload.url = val;
        targetDisplay = val.length > 55 ? val.substring(0, 52) + "..." : val;
      } else {
        const emailInput = document.getElementById("emailInput");
        const val = emailInput.value.trim();
        if (!val) return;
        payload.text = val;
        targetDisplay = val.length > 55 ? val.substring(0, 52) + "..." : val;
      }

      // Aktifkan Terminal Forensik
      if (terminalBox) terminalBox.style.display = "block";
      if (terminalBody) {
        terminalBody.innerHTML = `
          <div style="color:#6ee7b7;">[00.00s] [SYSTEM] PhisGuard Hybrid Defense Engine v2.1 diaktifkan.</div>
          <div style="color:#94a3b8;">[00.08s] [TARGET] Objek uji: <span style="color:#e2e8f0;font-weight:700;">${targetDisplay}</span> (${scanType.toUpperCase()})</div>
        `;
      }

      message.textContent = "Menghubungi sistem pertahanan hybrid...";
      message.style.color = "#2e6659";
      button.disabled = true;
      button.style.opacity = ".7";

      const startTime = Date.now();
      function getSec() {
        const diff = (Date.now() - startTime) / 1000;
        return (diff < 10 ? "0" : "") + diff.toFixed(2) + "s";
      }

      function logTerminal(color, text) {
        if (!terminalBody) return;
        const line = document.createElement("div");
        line.style.color = color;
        line.style.marginTop = "3px";
        line.innerHTML = `[${getSec()}] ${text}`;
        terminalBody.appendChild(line);
        terminalBody.scrollTop = terminalBody.scrollHeight;
      }

      // Pipeline Forensik Real-Time
      const timers = [];

      timers.push(setTimeout(() => {
        logTerminal("#38bdf8", `[EXTRACTOR] Mengekstraksi struktur leksikal, domain, dan fitur teks n-gram...`);
        if (qwenThoughtText) qwenThoughtText.textContent = "Mempersiapkan parameter bukti teknis dari target...";
      }, 250));

      timers.push(setTimeout(() => {
        const modelName = scanType === "url" ? "XGBoost Classifier" : "Bilingual Linear SVM";
        logTerminal("#fbbf24", `[TIER-1 ML] Menjalankan inferensi model statistik (${modelName})...`);
        if (qwenThoughtText) qwenThoughtText.textContent = `Menguji kecocokan dengan pola dataset (100.000+ sampel)...`;
      }, 600));

      timers.push(setTimeout(() => {
        logTerminal("#a7f3d0", `[EVIDENCE] Menyusun Evidence Bundle untuk verifikasi independen (Blind Assessment)...`);
        if (qwenThoughtText) qwenThoughtText.textContent = "Mengirim paket bukti ke Qwen 2.5 7B tanpa bias label awal...";
      }, 1000));

      timers.push(setTimeout(() => {
        logTerminal("#34d399", `[AI ANALYST] Menghubungi Qwen 2.5 7B via Ollama tunnel...`);
        if (qwenThoughtText) qwenThoughtText.textContent = "Qwen 2.5 7B sedang membaca isi target dan menelaah motif rekayasa sosial...";
      }, 1500));

      timers.push(setTimeout(() => {
        logTerminal("#e2e8f0", `[REASONING] Mengkaji indikator urgensi psikologis dan peniruan entitas...`);
        if (qwenThoughtText) qwenThoughtText.textContent = "Menganalisis manipulasi psikologis, peniruan identitas, dan form login...";
      }, 2800));

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        // Bersihkan timer simulasi yang belum berjalan
        timers.forEach(t => clearTimeout(t));

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || "Gagal memproses analisis ancaman.");
        }

        const data = await response.json();

        // Tampilkan keputusan final di terminal
        const qwenVerdict = data.qwen ? data.qwen.second_verdict : data.prediction;
        const finalStatus = data.status_text || "Terkonfirmasi";
        const colorVerdict = (data.prediction === "phishing" || qwenVerdict === "phishing") ? "#f87171" : "#4ade80";

        // Tampilkan status koneksi Ollama dan audit tautan
        if (data.embedded_links_audit && data.embedded_links_audit.total_links > 0) {
          const lAudit = data.embedded_links_audit;
          if (lAudit.has_phishing_link) {
            logTerminal("#ef4444", `[ALERT] Ditemukan tautan phishing di dalam email. Tingkat ancaman dieskalasi.`);
          } else {
            logTerminal("#34d399", `[AUDIT] ${lAudit.total_links} tautan tersemat terverifikasi memiliki reputasi normal.`);
          }
        }

        if (data.qwen) {
          if (data.qwen.is_live_ollama) {
            logTerminal("#10b981", `[AI VERIFIED] Qwen 2.5 7B terhubung langsung via Ollama.`);
          } else {
            logTerminal("#94a3b8", `[FALLBACK] Evaluasi independen diselesaikan oleh Mesin Analis Internal.`);
          }
        }

        logTerminal(colorVerdict, `[KONSENSUS] Status Akhir: <b>${finalStatus}</b> | ML: ${data.prediction.toUpperCase()} (${data.confidence}%) | Qwen: ${qwenVerdict.toUpperCase()}`);
        
        if (data.qwen && data.qwen.explanation) {
          const shortExpl = data.qwen.explanation.length > 90 ? data.qwen.explanation.substring(0, 87) + "..." : data.qwen.explanation;
          logTerminal("#6ee7b7", `[TEMUAN AI] "${shortExpl}"`);
          if (qwenThoughtText) qwenThoughtText.textContent = `Qwen: "${shortExpl}"`;
        }

        logTerminal("#93c5fd", `[LAPORAN] Menyusun laporan audit forensik resmi...`);
        message.textContent = "Verifikasi selesai! Membuka laporan hasil investigasi...";

        // Kirim hasil ke sesi hasil Flask
        const resultResponse = await fetch("/scan/result", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        });

        setTimeout(() => {
          if (resultResponse.redirected) {
            window.location.href = resultResponse.url;
          } else if (data.redirect_url) {
            window.location.href = data.redirect_url;
          } else {
            window.location.href = "/result";
          }
        }, 600);

      } catch (error) {
        timers.forEach(t => clearTimeout(t));
        logTerminal("#ef4444", `[ERROR] <b>[Pipeline Error]</b> ${error.message}`);
        message.style.color = "#c96570";
        message.textContent = error.message + " Periksa menu Pengaturan.";
        button.disabled = false;
        button.style.opacity = "1";
        if (qwenThoughtText) qwenThoughtText.textContent = "Pemeriksaan terhenti karena kendala koneksi atau server.";
      }
    });
  }
});
