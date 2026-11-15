document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));

  const form = document.getElementById("scanForm");
  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = document.getElementById("formMessage");
      const button = form.querySelector("button[type=submit]");
      const scanType = document.getElementById("scanType") ? document.getElementById("scanType").value : "url";
      const pipelineBox = document.getElementById("pipelineProgress");
      
      let payload = { type: scanType };
      if (scanType === "url") {
        const urlInput = document.getElementById("urlInput");
        const val = urlInput.value.trim();
        if (!val) return;
        payload.url = val;
      } else {
        const emailInput = document.getElementById("emailInput");
        const val = emailInput.value.trim();
        if (!val) return;
        payload.text = val;
      }

      // Aktifkan Tampilan Pipeline
      if (pipelineBox) pipelineBox.style.display = "block";
      message.textContent = "Menghubungi sistem pertahanan hybrid...";
      message.style.color = "#2e6659";
      button.disabled = true;
      button.style.opacity = ".7";

      function updateStep(stepId, state) {
        const el = document.getElementById(stepId);
        if (!el) return;
        const num = el.querySelector(".flow-num");
        if (state === "active") {
          el.style.color = "#183b32";
          el.style.fontWeight = "700";
          if (num) {
            num.style.background = "#2e6659";
            num.style.color = "#ffffff";
          }
        } else if (state === "done") {
          el.style.color = "#2e6659";
          if (num) {
            num.style.background = "#1b4d3e";
            num.style.color = "#ffffff";
            num.textContent = "✓";
          }
        }
      }

      // Animasi alur kerja
      updateStep("pstep1", "active");
      const t1 = setTimeout(() => {
        updateStep("pstep1", "done");
        updateStep("pstep2", "active");
      }, 350);

      const t2 = setTimeout(() => {
        updateStep("pstep2", "done");
        updateStep("pstep3", "active");
      }, 750);

      const t3 = setTimeout(() => {
        updateStep("pstep3", "done");
        updateStep("pstep4", "active");
        message.textContent = "Qwen 2.5 7B sedang mengevaluasi konteks & rekayasa sosial...";
      }, 1200);

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        clearTimeout(t1);
        clearTimeout(t2);
        clearTimeout(t3);

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || "Gagal memproses analisis ancaman.");
        }

        const data = await response.json();

        // Tandai step 4 & 5 selesai
        updateStep("pstep1", "done");
        updateStep("pstep2", "done");
        updateStep("pstep3", "done");
        updateStep("pstep4", "done");
        updateStep("pstep5", "done");
        message.textContent = "Verifikasi selesai! Menyiapkan hasil & laporan PDF...";

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
        }, 400);

      } catch (error) {
        message.style.color = "#c96570";
        message.textContent = error.message + " Pastikan server berjalan normal.";
        button.disabled = false;
        button.style.opacity = "1";
      }
    });
  }
});
