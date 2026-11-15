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

      message.textContent = "Sedang mengekstraksi fitur & menjalankan inferensi ML + verifikasi Qwen 2.5 7B…";
      message.style.color = "#5c9f88";
      button.disabled = true;
      button.style.opacity = ".7";

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || "Gagal memproses analisis ancaman.");
        }

        const data = await response.json();

        // Kirim hasil ke sesi hasil Flask
        const resultResponse = await fetch("/scan/result", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        });

        if (resultResponse.redirected) {
          window.location.href = resultResponse.url;
        } else if (data.redirect_url) {
          window.location.href = data.redirect_url;
        } else {
          window.location.href = "/result";
        }
      } catch (error) {
        message.style.color = "#c96570";
        message.textContent = error.message + " Pastikan server berjalan normal.";
      } finally {
        button.disabled = false;
        button.style.opacity = "1";
      }
    });
  }
});
