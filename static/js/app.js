document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));

  // Dynamic Model Name State
  let globalModelName = "Qwen 2.5 7B";

  // Status Sistem Keamanan (User-Friendly, Non-Developer)
  const topBadge = document.getElementById("topEngineBadge");
  const topDot = document.getElementById("topEngineDot");
  const topText = document.getElementById("topEngineText");
  const badgeModelName = document.getElementById("badgeModelName");

  const radioHybrid = document.getElementById("scanModeHybrid");
  const radioMandiri = document.getElementById("scanModeMandiri");
  const labelHybrid = document.getElementById("labelModeHybrid");
  const labelMandiri = document.getElementById("labelModeMandiri");

  async function updateTopEngineBadge() {
    try {
      const res = await fetch("/api/ollama-status");
      const data = await res.json();
      if (data.model_name) {
        globalModelName = data.model_name;
        document.querySelectorAll(".dyn-model-name").forEach(el => el.textContent = globalModelName);
        if (badgeModelName) badgeModelName.textContent = `${globalModelName} ${data.status === 'online' ? 'Siap' : 'Offline'}`;
      }

      if (!topBadge || !topDot || !topText) return;

      // 1. Jika di halaman Result (/result) atau Analysis (/analysis), ikuti mode hasil laporan yang sedang dibuka
      const resultBanner = document.getElementById("resultBanner") || document.getElementById("analysisBanner");
      if (resultBanner) {
        const reportMode = resultBanner.getAttribute("data-engine-mode");
        const customModel = resultBanner.getAttribute("data-model-name") || globalModelName;
        if (reportMode === "hybrid") {
          topDot.style.background = "#10b981";
          topDot.style.boxShadow = "0 0 0 2px rgba(16,185,129,0.25)";
          topText.textContent = "Proteksi Hybrid Aktif";
          topBadge.title = `Laporan diverifikasi oleh Dual-Engine: Supervised ML + ${customModel}.`;
          topBadge.style.borderColor = "#a7f3d0";
          topBadge.style.background = "#ecfdf5";
          topBadge.style.color = "#065f46";
          return;
        } else if (reportMode === "fallback") {
          topDot.style.background = "#f59e0b";
          topDot.style.boxShadow = "0 0 0 2px rgba(245,158,11,0.25)";
          topText.textContent = "Mandiri (LLM Offline)";
          topBadge.title = "Laporan dialihkan ke Mode Mandiri karena server LLM offline.";
          topBadge.style.borderColor = "#fde68a";
          topBadge.style.background = "#fffbeb";
          topBadge.style.color = "#92400e";
          return;
        } else {
          topDot.style.background = "#64748b";
          topDot.style.boxShadow = "0 0 0 2px rgba(100,116,139,0.25)";
          topText.textContent = "Mode Mandiri (ML)";
          topBadge.title = "Laporan diproses 100% oleh model Supervised Machine Learning.";
          topBadge.style.borderColor = "#cbd5e1";
          topBadge.style.background = "#f1f5f9";
          topBadge.style.color = "#475569";
          return;
        }
      }

      // 2. Jika di halaman Scan (/scan), ikuti pilihan mode pengguna secara real-time
      if (radioMandiri && radioMandiri.checked) {
        topDot.style.background = "#64748b";
        topDot.style.boxShadow = "0 0 0 2px rgba(100,116,139,0.25)";
        topText.textContent = "Mode Mandiri (ML)";
        topBadge.title = "Mode Mandiri Dipilih: Scan dieksekusi instan oleh Supervised ML tanpa memanggil LLM.";
        topBadge.style.borderColor = "#cbd5e1";
        topBadge.style.background = "#f1f5f9";
        topBadge.style.color = "#475569";
      } else if (data.status === "online") {
        topDot.style.background = "#10b981";
        topDot.style.boxShadow = "0 0 0 2px rgba(16,185,129,0.25)";
        topText.textContent = "Proteksi Hybrid Aktif";
        topBadge.title = `Konsensus Dual-Engine Siap: Supervised ML + ${globalModelName} Aktif.`;
        topBadge.style.borderColor = "#a7f3d0";
        topBadge.style.background = "#ecfdf5";
        topBadge.style.color = "#065f46";
      } else {
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
        if (radioHybrid && radioHybrid.checked && data.status !== "online") {
          hybridNotice.style.display = "block";
        } else {
          hybridNotice.style.display = "none";
        }
      }
    } catch (e) {
      if (topDot && topText && topBadge) {
        topDot.style.background = "#10b981";
        topDot.style.boxShadow = "0 0 0 2px rgba(16,185,129,0.25)";
        topText.textContent = "Proteksi AI Aktif";
        topBadge.style.borderColor = "#a7f3d0";
        topBadge.style.background = "#ecfdf5";
        topBadge.style.color = "#065f46";
      }
    }
  }

  updateTopEngineBadge();

  // Mode Selection Styling and State Tracking
  function updateModeCardStyles() {
    if (radioHybrid && radioMandiri && labelHybrid && labelMandiri) {
      if (radioHybrid.checked) {
        labelHybrid.style.borderColor = "#10b981";
        labelHybrid.style.background = "#f0fdf4";
        labelMandiri.style.borderColor = "#e2e8f0";
        labelMandiri.style.background = "#ffffff";
        sessionStorage.setItem("phisguard_draft_mode", "hybrid");
      } else {
        labelMandiri.style.borderColor = "#10b981";
        labelMandiri.style.background = "#f0fdf4";
        labelHybrid.style.borderColor = "#e2e8f0";
        labelHybrid.style.background = "#ffffff";
        sessionStorage.setItem("phisguard_draft_mode", "mandiri");
      }
    }
  }

  if (radioHybrid) radioHybrid.addEventListener("change", () => { updateModeCardStyles(); updateTopEngineBadge(); });
  if (radioMandiri) radioMandiri.addEventListener("change", () => { updateModeCardStyles(); updateTopEngineBadge(); });

  // Form Draft Persistence via sessionStorage
  const urlInput = document.getElementById("urlInput");
  const emailInput = document.getElementById("emailInput");

  // Restore drafts on load ONLY if user was in the middle of typing
  try {
    const savedUrl = sessionStorage.getItem("phisguard_draft_url");
    const savedEmail = sessionStorage.getItem("phisguard_draft_email");
    const savedMode = sessionStorage.getItem("phisguard_draft_mode");

    if (savedUrl && urlInput && !urlInput.value) urlInput.value = savedUrl;
    if (savedEmail && emailInput && !emailInput.value) emailInput.value = savedEmail;
    if (savedMode === "mandiri" && radioMandiri) {
      radioMandiri.checked = true;
      updateModeCardStyles();
      updateTopEngineBadge();
    } else if (savedMode === "hybrid" && radioHybrid) {
      radioHybrid.checked = true;
      updateModeCardStyles();
      updateTopEngineBadge();
    }
  } catch (e) {
    // SessionStorage unavailable or restricted
  }

  // Save drafts on user typing
  if (urlInput) urlInput.addEventListener("input", () => sessionStorage.setItem("phisguard_draft_url", urlInput.value));
  if (emailInput) emailInput.addEventListener("input", () => sessionStorage.setItem("phisguard_draft_email", emailInput.value));

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

      const selectedMode = (radioMandiri && radioMandiri.checked) ? "mandiri" : "hybrid";

      let payload = { 
        type: scanType,
        mode: selectedMode
      };
      let targetDisplay = "";

      if (scanType === "url") {
        const val = urlInput.value.trim();
        if (!val) return;
        payload.url = val;
        targetDisplay = val.length > 55 ? val.substring(0, 52) + "..." : val;
      } else {
        const val = emailInput.value.trim();
        if (!val) return;
        payload.text = val;
        targetDisplay = val.length > 55 ? val.substring(0, 52) + "..." : val;
      }

      // Aktifkan Terminal Forensik
      if (terminalBox) terminalBox.style.display = "block";
      if (terminalBody) {
        terminalBody.innerHTML = `
          <div style="color:#6ee7b7;">[00.00s] [SYSTEM] PhisGuard Defense Engine v2.1 diaktifkan (${selectedMode.toUpperCase()} MODE).</div>
          <div style="color:#94a3b8;">[00.08s] [TARGET] Objek uji: <span style="color:#e2e8f0;font-weight:700;">${targetDisplay}</span> (${scanType.toUpperCase()})</div>
        `;
      }

      message.textContent = selectedMode === "hybrid" 
        ? "Menghubungi sistem pertahanan hybrid & verifikasi mendalam..." 
        : "Menjalankan klasifikasi Supervised Machine Learning (<50ms)...";
      message.style.color = "#2e6659";
      button.disabled = true;
      button.style.opacity = ".7";
      const btnText = document.getElementById("btnText");
      if (btnText) {
        btnText.innerHTML = `<span class="spin-icon" style="margin-right:6px;vertical-align:middle;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10" stroke-opacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10"/></svg></span><span>Menganalisis...</span>`;
      }

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
      }, 550));

      if (selectedMode === "hybrid") {
        timers.push(setTimeout(() => {
          logTerminal("#a7f3d0", `[WEB INSPECT] Memeriksa live HTTP status, redirect, dan form kredensial...`);
          if (qwenThoughtText) qwenThoughtText.textContent = "Melakukan live deep crawl & ekstraksi form login...";
        }, 900));

        timers.push(setTimeout(() => {
          logTerminal("#34d399", `[AI ANALYST] Mengirim Evidence Bundle ke ${globalModelName}...`);
          if (qwenThoughtText) qwenThoughtText.textContent = `${globalModelName} sedang menelaah narasi kontekstual & motif rekayasa sosial...`;
        }, 1600));

        timers.push(setTimeout(() => {
          logTerminal("#e2e8f0", `[REASONING] Mengkaji indikator urgensi psikologis, peniruan entitas, dan ancaman...`);
          if (qwenThoughtText) qwenThoughtText.textContent = "Menganalisis manipulasi emosional, impersonation, dan link harvesting...";
        }, 3200));

        timers.push(setTimeout(() => {
          logTerminal("#38bdf8", `[INFERENCE] Menunggu sinkronisasi inferensi bahasa alami (${globalModelName})...`);
        }, 6000));
      } else {
        timers.push(setTimeout(() => {
          logTerminal("#94a3b8", `[MODE MANDIRI] Melewati panggilan LLM. Menyelesaikan verifikasi berbasis statistik terkalibrasi.`);
          if (qwenThoughtText) qwenThoughtText.textContent = "Mode Mandiri aktif: Keputusan langsung dari model Supervised ML.";
        }, 750));
      }

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

        // Bersihkan draft dari sessionStorage agar tidak nyangkut untuk scan berikutnya
        try {
          sessionStorage.removeItem("phisguard_draft_url");
          sessionStorage.removeItem("phisguard_draft_email");
        } catch (e) {}

        // Tampilkan keputusan final di terminal
        const qwenVerdict = data.qwen ? data.qwen.second_verdict : data.prediction;
        const finalStatus = data.status_text || "Terkonfirmasi";
        const colorVerdict = (data.prediction === "phishing" || qwenVerdict === "phishing") ? "#f87171" : "#4ade80";

        // Tampilkan audit tautan jika ada
        if (data.embedded_links_audit && data.embedded_links_audit.total_links > 0) {
          const lAudit = data.embedded_links_audit;
          if (lAudit.has_phishing_link) {
            logTerminal("#ef4444", `[ALERT] Ditemukan tautan phishing di dalam pesan. Tingkat ancaman dieskalasi.`);
          } else {
            logTerminal("#34d399", `[AUDIT] ${lAudit.total_links} tautan tersemat diverifikasi memiliki reputasi normal.`);
          }
        }

        // Tampilkan status Live Web Inspection jika ada
        if (data.live_inspection && data.live_inspection.http_status && data.live_inspection.http_status !== "Belum Terhubung") {
          logTerminal("#38bdf8", `[LIVE WEB] Status: ${data.live_inspection.http_status} | Judul: "${data.live_inspection.page_title || '-'}"`);
        }

        if (data.qwen) {
          if (data.qwen.is_live_ollama) {
            logTerminal("#10b981", `[AI VERIFIED] ${data.qwen.source || globalModelName} berhasil memvalidasi konteks.`);
          } else if (data.qwen.engine_mode === "fallback_mandiri") {
            logTerminal("#f59e0b", `[FALLBACK] Server LLM offline. Evaluasi dialihkan ke Mode Mandiri.`);
          } else {
            logTerminal("#94a3b8", `[MODE MANDIRI] Pemeriksaan diselesaikan secara mandiri oleh ML Engine.`);
          }
        }

        logTerminal(colorVerdict, `[KONSENSUS] Status Akhir: <b>${finalStatus}</b> | ML: ${data.prediction.toUpperCase()} (${data.confidence}%) | AI: ${qwenVerdict.toUpperCase()}`);
        
        if (data.qwen && data.qwen.explanation) {
          const shortExpl = data.qwen.explanation.length > 90 ? data.qwen.explanation.substring(0, 87) + "..." : data.qwen.explanation;
          logTerminal("#6ee7b7", `[TEMUAN AI] "${shortExpl}"`);
          if (qwenThoughtText) qwenThoughtText.textContent = `Temuan: "${shortExpl}"`;
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
        }, 500);

      } catch (error) {
        timers.forEach(t => clearTimeout(t));
        logTerminal("#ef4444", `[ERROR] <b>[Pipeline Error]</b> ${error.message}`);
        message.style.color = "#c96570";
        message.textContent = error.message + " Periksa menu Pengaturan.";
        button.disabled = false;
        button.style.opacity = "1";
        if (btnText) btnText.textContent = "Mulai Analisis Keamanan";
        if (qwenThoughtText) qwenThoughtText.textContent = "Pemeriksaan terhenti karena kendala koneksi atau server.";
      }
    });
  }
});
