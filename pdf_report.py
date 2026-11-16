"""
PhisGuard PDF Security Investigation Report Generator
Menghasilkan dokumen PDF laporan resmi investigasi ancaman phishing
berdasarkan Bab 11 & Bab 10 Dokumen Rancangan Konsep Proyek Keamanan Informasi.
"""

import io
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(result_data: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    # A4: 595.27 x 841.89 points. Margins 36pt (0.5 inch). Printable width: 523.27pt.
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Colors (Mint / Forest Green / Charcoal / Warning Rose)
    primary_color = colors.HexColor("#1b4d3e")
    secondary_color = colors.HexColor("#2e6659")
    accent_color = colors.HexColor("#3d8b76")
    danger_color = colors.HexColor("#b3261e")
    safe_color = colors.HexColor("#1e7e34")
    warning_color = colors.HexColor("#c26100")
    dark_text = colors.HexColor("#1a1c1e")
    muted_text = colors.HexColor("#525854")
    border_color = colors.HexColor("#c8e7d9")
    bg_light = colors.HexColor("#f4fbf8")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=primary_color,
        fontName="Helvetica-Bold",
        spaceAfter=2
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=muted_text,
        spaceAfter=10
    )

    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=primary_color,
        fontName="Helvetica-Bold",
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=dark_text
    )

    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    callout_style = ParagraphStyle(
        "CalloutText",
        parent=body_style,
        fontSize=8.5,
        leading=13,
        textColor=colors.HexColor("#183b32")
    )

    story = []

    # 1. Header Laporan Resmi
    story.append(Paragraph("PHISGUARD — LAPORAN INVESTIGASI KEAMANAN", title_style))
    story.append(Paragraph("Sistem Verifikasi Phishing Berlapis (Machine Learning + Qwen 2.5 7B Local LLM)", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=primary_color, spaceAfter=8))

    # Variabel Data
    analysis_id = result_data.get("analysis_id", f"PG-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}")
    now_str = datetime.datetime.now().strftime("%d %B %Y, %H:%M WIB")
    target = result_data.get("url", "-")
    input_type = result_data.get("input_type", "URL").upper()
    prediction = result_data.get("prediction", "unknown").upper()
    confidence = result_data.get("confidence", 0.0)
    qwen = result_data.get("qwen", {})
    second_verdict = qwen.get("second_verdict", "inconclusive").upper()
    reconciliation_status = result_data.get("status_text", "Selesai")
    treatment = qwen.get("treatment", "Verifikasi berlapis selesai.")
    model_name = result_data.get("model_name", "Supervised ML Model")

    is_phish = prediction == "PHISHING"
    badge_color = danger_color if is_phish else safe_color

    # BAGIAN 1: RINGKASAN KASUS (Metadata Box)
    story.append(Paragraph("1. Ringkasan Investigasi (Executive Summary)", h2_style))
    meta_data = [
        [Paragraph("ID Analisis", body_bold), Paragraph(analysis_id, body_style),
         Paragraph("Waktu Audit", body_bold), Paragraph(now_str, body_style)],
        [Paragraph("Tipe Input", body_bold), Paragraph(input_type, body_style),
         Paragraph("Status Rekonsiliasi", body_bold), Paragraph(f"<b>{reconciliation_status}</b>", body_style)],
        [Paragraph("Target Objek", body_bold), Paragraph(target[:75] + ("..." if len(target) > 75 else ""), body_style),
         Paragraph("Keputusan Akhir", body_bold), Paragraph(f"<font color='{badge_color}'><b>{prediction} ({confidence}%)</b></font>", body_style)]
    ]

    t_meta = Table(meta_data, colWidths=[80, 180, 110, 150])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))

    # BAGIAN 2 & 3: HASIL DETEKSI GANDA (ML vs Qwen 2.5 7B)
    story.append(Paragraph("2 & 3. Perbandingan Detektor ML vs Verifikator Qwen 2.5 7B", h2_style))
    comp_data = [
        [
            Paragraph("<b>2. Detektor Awal: Machine Learning</b>", body_style),
            Paragraph("<b>3. Pemeriksa Kedua: Qwen 2.5 7B (Ollama)</b>", body_style)
        ],
        [
            Paragraph(
                f"• <b>Arsitektur:</b> {model_name}<br/>"
                f"• <b>Label Prediksi:</b> <b>{prediction}</b><br/>"
                f"• <b>Keyakinan Statistik:</b> {confidence}%<br/>"
                f"• <b>Metode Evaluasi:</b> Klasifikasi probabilitas fitur kuantitatif",
                body_style
            ),
            Paragraph(
                f"• <b>Model:</b> Qwen 2.5 7B (Local Offline Instance)<br/>"
                f"• <b>Second Verdict:</b> <b>{second_verdict}</b><br/>"
                f"• <b>Status Konsensus:</b> {reconciliation_status}<br/>"
                f"• <b>Metode Evaluasi:</b> Blind Assessment (Konteks & Bukti)",
                body_style
            )
        ]
    ]

    t_comp = Table(comp_data, colWidths=[260, 260])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#eef7f3")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#e5f4ef")),
        ('BACKGROUND', (0,1), (-1,1), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 8))

    # BAGIAN 4: BUKTI TEKNIS & FITUR EKSTRAKSI
    story.append(Paragraph("4. Bukti Teknis & Parameter Ekstraksi", h2_style))
    features = result_data.get("features", {})
    feat_rows = [[Paragraph("<b>Parameter Keamanan</b>", body_style), Paragraph("<b>Hasil Pengamatan Teknis</b>", body_style)]]
    for k, v in features.items():
        feat_rows.append([Paragraph(k, body_style), Paragraph(str(v), body_style)])

    t_feat = Table(feat_rows, colWidths=[180, 340])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#eaf5ee")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 8))

    # BAGIAN 5: INDIKATOR ANCAMAN & REKAYASA SOSIAL
    story.append(Paragraph("5. Indikator Ancaman & Pola Rekayasa Sosial", h2_style))
    soc_eng = qwen.get("social_engineering", {})
    urgency = soc_eng.get("urgency_level", "Sedang" if is_phish else "Rendah")
    impersonation = soc_eng.get("impersonation", "Terindikasi peniruan entitas resmi" if is_phish else "Tidak terindikasi")
    cred_harvest = "Ya, terindikasi form/link pengumpulan data" if soc_eng.get("credential_harvesting", is_phish) else "Tidak ditemukan form kredensial"

    soc_data = [
        [Paragraph("Tingkat Urgensi Psikologis", body_bold), Paragraph(urgency, body_style)],
        [Paragraph("Upaya Peniruan Identitas (Impersonation)", body_bold), Paragraph(impersonation, body_style)],
        [Paragraph("Sinyal Credential Harvesting", body_bold), Paragraph(cred_harvest, body_style)],
    ]
    t_soc = Table(soc_data, colWidths=[180, 340])
    t_soc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#fcfdfd")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_soc)
    story.append(Spacer(1, 6))

    indicators = qwen.get("indicators", [])
    if indicators:
        story.append(Paragraph("<b>Daftar Indikator Spesifik yang Ditemukan:</b>", body_bold))
        for ind in indicators:
            story.append(Paragraph(f"• {ind}", body_style))
        story.append(Spacer(1, 6))

    # BAGIAN 6: ANALISIS POTENSI TUJUAN SERANGAN (Dugaan Berbasis Bukti)
    story.append(Paragraph("6. Analisis Potensi Tujuan Serangan (Dugaan)", h2_style))
    objective = soc_eng.get("potential_objective")
    if not objective:
        objective = "Pencurian kredensial akun pengguna, pengelabuan sesi login, atau manipulasi transaksi." if is_phish else "Tidak ditemukan indikasi motif serangan berbahaya."
    explanation = qwen.get("explanation") or result_data.get("recommendation") or "Analisis konteks selesai."
    
    analysis_narrative = (
        f"<b>Dugaan Motif Ancaman:</b> {objective}<br/>"
        f"<b>Catatan Evaluator:</b> {explanation} "
        f"<i>(Catatan: Seluruh analisis tujuan di atas dikategorikan sebagai dugaan berbasis bukti dan membutuhkan konfirmasi lanjutan).</i>"
    )
    story.append(Paragraph(analysis_narrative, callout_style))
    story.append(Spacer(1, 8))

    # BAGIAN 7: KESIMPULAN REKONSILIASI
    story.append(Paragraph("7. Kesimpulan Rekonsiliasi Hasil (Bab 10)", h2_style))
    reconcil_text = (
        f"Berdasarkan matriks rekonsiliasi antara Machine Learning dan Qwen 2.5 7B, sistem menetapkan status "
        f"<b>'{reconciliation_status}'</b>. {treatment}"
    )
    story.append(Paragraph(reconcil_text, body_style))
    story.append(Spacer(1, 8))

    # BAGIAN 8: REKOMENDASI TINDAKAN KEAMANAN
    story.append(Paragraph("8. Rekomendasi Tindakan Keamanan & Mitigasi", h2_style))
    recom = result_data.get("recommendation", "Pastikan verifikasi selalu dilakukan melalui kanal resmi.")
    mitigation_points = [
        f"<b>Bagi Pengguna:</b> {recom}",
        "<b>Bagi Administrator:</b> Tinjau log DNS/mail gateway, blokir indikator IOC jika status sepakat berbahaya, dan edukasi personel terhadap teknik rekayasa sosial serupa."
    ]
    for m in mitigation_points:
        story.append(Paragraph(f"• {m}", body_style))
    story.append(Spacer(1, 8))

    # BAGIAN 9: LIMITASI SISTEM & BATAS KLAIM (Bab 11 Poin 9)
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray, spaceAfter=6))
    story.append(Paragraph("9. Batas Klaim & Limitasi Sistem", ParagraphStyle("LimH", parent=body_bold, fontSize=8, textColor=muted_text)))
    limitasi_text = (
        "Laporan investigasi ini disusun secara otomatis oleh PhisGuard AI menggunakan perpaduan model Machine Learning "
        "(analisis fitur terstruktur) dan Qwen 2.5 7B Local LLM (analisis konteks independen). "
        "Keyakinan model LLM bersifat kualitatif dan tidak setara dengan probabilitas statistik absolut. "
        "Status 'Legitimate' mengindikasikan ketiadaan bukti serangan yang signifikan pada fitur statis yang diuji, "
        "bukan jaminan keamanan mutlak. Verifikasi manual melalui kanal komunikasi resmi selalu disarankan untuk transaksi berisiko tinggi."
    )
    story.append(Paragraph(limitasi_text, ParagraphStyle("LimText", parent=body_style, fontSize=7, leading=9.5, textColor=muted_text)))

    doc.build(story)
    buffer.seek(0)
    return buffer
