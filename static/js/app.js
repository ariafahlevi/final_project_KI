document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));

  const form = document.getElementById("scanForm");
  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const input = document.getElementById("urlInput");
      const message = document.getElementById("formMessage");
      const button = form.querySelector("button[type=submit]");
      const url = input.value.trim();
      if (!url) return;
      message.textContent = "Sedang menganalisis URL…";
      message.style.color = "#5c9f88";
      button.disabled = true;
      button.style.opacity = ".7";
      try {
        // Endpoint kontrak awal. Sesuaikan nama endpoint/format respons dengan backend Flask kelompok.
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({url})
        });
        if (!response.ok) throw new Error("API belum tersedia atau terjadi kesalahan.");
        const data = await response.json();
        // Backend diharapkan mengembalikan prediction, confidence, features, recommendation.
        const resultResponse = await fetch("/scan/result", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(data)
        });
        if (resultResponse.redirected) window.location.href = resultResponse.url;
        else if (data.redirect_url) window.location.href = data.redirect_url;
        else {
          sessionStorage.setItem("phishguard_last_result", JSON.stringify(data));
          message.textContent = "Analisis selesai. Hubungkan redirect hasil pada backend Flask.";
        }
      } catch (error) {
        message.style.color = "#c96570";
        message.textContent = error.message + " Periksa koneksi backend Flask.";
      } finally {
        button.disabled = false;
        button.style.opacity = "1";
      }
    });
  }
});
