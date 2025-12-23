import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import streamlit as st

# ================== Konfigurasi ==================
REPORT_FILE = Path("reports/report_final.json")

st.set_page_config(
    page_title="📧 Phishing Email Analyzer",
    layout="wide",
    page_icon="🔍",
)

# ================== Fungsi Utilitas ==================
def load_report():
    """Memuat data JSON hasil analisis phishing"""
    if REPORT_FILE.exists():
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            st.error("❌ Gagal memuat report_final.json. Format file tidak valid.")
            return []
    else:
        st.warning("⚠ File report_final.json tidak ditemukan. Jalankan analisis dulu.")
        return []

def vt_link_url(vt_data):
    vt_id = vt_data.get("id") or vt_data.get("scan_id")
    return f"https://www.virustotal.com/gui/url/{vt_id}" if vt_id else None

def badge(text, color):
    """Membuat badge warna HTML untuk status"""
    return f"<span style='background:{color}; color:white; padding:3px 7px; border-radius:6px; font-size:0.8em; font-weight:600;'>{text}</span>"

# ================== Load Data ==================
report_data = load_report()
if not report_data:
    st.stop()

# ================== Sidebar Navigasi ==================
st.sidebar.title("📌 Menu")
page = st.sidebar.radio("", ["📊 Dashboard", "📈 Statistik", "ℹ Tentang"])
st.sidebar.markdown("---")
st.sidebar.info(
    "📁 Letakkan file `.eml` di folder `data/` lalu jalankan `analyze.py` sebelum membuka dashboard."
)

# ================== Halaman DASHBOARD ==================
if page == "📊 Dashboard":
    st.title("📧 Email Phishing Analyzer")

    # Urutkan email berdasarkan nama file (alfabetis)
    sorted_data = sorted(report_data, key=lambda d: d.get("file_name", "").lower())
    email_names = [d.get("file_name", f"Email {i+1}") for i, d in enumerate(sorted_data)]

    # Dropdown Email
    selected_index = st.selectbox(
        "Pilih Email:", range(len(email_names)), format_func=lambda i: email_names[i]
    )
    selected_email = sorted_data[selected_index]
    headers = selected_email.get("headers", {})

    # ===== Ringkasan Header =====
    st.markdown(f"### ✉ **{selected_email.get('file_name')}**")
    col1, col2, col3 = st.columns(3)
    col1.metric("From", headers.get("from") or "—")
    col2.metric("To", headers.get("to") or "—")
    col3.metric("Date", headers.get("date") or "—")
    st.markdown("---")

    # ===== SpamAssassin =====
    st.subheader("🧠 SpamAssassin Analysis")
    sa = selected_email.get("spamassassin", {})
    score = sa.get("score", 0.0)

    raw_is_spam = sa.get("is_spam")
    is_spam = False

    # Normalisasi skor dan status
    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0

        if score >= 5.0:
            is_spam = True
        elif score <= 0.0:
            is_spam = False
        else:
            if isinstance(raw_is_spam, bool):
                is_spam = raw_is_spam
            elif isinstance(raw_is_spam, str):
                is_spam = raw_is_spam.lower() in ["true", "1", "yes"]

    color = "#c0392b" if is_spam else "#27ae60"  # merah / hijau
    text = "🚨 SPAM" if is_spam else "✅ Legit"
    st.markdown(
        f"<div style='padding:10px; border-radius:8px; background-color:{color}; color:white; font-weight:bold; text-align:center;'>{text} — Score: {score}</div>",
        unsafe_allow_html=True,
    )

    with st.expander("📜 Detail SpamAssassin"):
        st.text(sa.get("full_report", "Tidak ada laporan lengkap"))
        if sa.get("tests"):
            st.write("**Rules Terdeteksi:**", ", ".join(sa["tests"]))
    st.markdown("---")

    # ===== URL Analysis =====
    st.subheader("🌐 URL Analysis")
    urls = selected_email.get("urls", [])
    vt_urls = selected_email.get("vt_url_analysis", [])

    if urls:
        table_data = []
        for i, url in enumerate(urls):
            vt_data = vt_urls[i] if i < len(vt_urls) else {}
            stats = vt_data.get("vt_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            # Status badge
            if malicious > 0:
                status = badge("Malicious", "#e74c3c")
            elif suspicious > 0:
                status = badge("Suspicious", "#f39c12")
            else:
                status = badge("Harmless", "#2ecc71")

            # Potong URL agar tabel tetap rapi
            short_url = url if len(url) <= 60 else f"{url[:35]}...{url[-20:]}"
            url_html = (
                f"<a href='{url}' target='_blank' title='{url}' "
                f"style='text-decoration:none; color:#2980b9;'>{short_url}</a>"
            )

            table_data.append([url_html, status, malicious, suspicious, harmless])

        df_url = pd.DataFrame(
            table_data,
            columns=["URL", "Status", "Malicious", "Suspicious", "Harmless"],
        )

        # Styling tabel agar lebih rapi
        st.markdown(
            """
            <style>
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                margin-bottom: 25px;
                font-size: 0.9em;
                border: 1px solid #ddd;
            }
            th {
                background-color: #f7f7f7;
                color: #333;
                padding: 10px;
                text-align: left;
                border-bottom: 2px solid #ccc;
            }
            td {
                padding: 8px;
                border-bottom: 1px solid #eee;
                vertical-align: middle;
            }
            tr:hover {background-color: #f9f9f9;}
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.write(df_url.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("Tidak ada URL ditemukan dalam email ini.")
    st.markdown("---")

    # ===== Header =====
    st.subheader("📬 Email Details")
    st.json(headers)

# ================== Halaman STATISTIK ==================
elif page == "📈 Statistik":
    st.title("📈 Statistik Analisis Global")

    total_email = len(report_data)
    total_spam = sum(
        1
        for d in report_data
        if float(d.get("spamassassin", {}).get("score", 0)) >= 5.0
    )
    total_urls = sum(len(d.get("urls", [])) for d in report_data)

    # Hitung jumlah URL berbahaya unik per email
    total_malicious_urls = 0
    malicious_per_email = []
    for d in report_data:
        count_malicious_urls = 0
        vt_results = d.get("vt_url_analysis", [])
        for vt in vt_results:
            stats = vt.get("vt_stats", {})
            if stats.get("malicious", 0) > 0:
                count_malicious_urls += 1
        total_malicious_urls += count_malicious_urls
        malicious_per_email.append(
            {"email": d.get("file_name", "Unknown"), "malicious_count": count_malicious_urls}
        )

    avg_malicious = total_malicious_urls / total_email if total_email else 0

    # ===== Statistik Ringkas =====
    st.markdown("### 📊 Ringkasan Analisis")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📧 Total Email", total_email)
    col2.metric("🚨 Email SPAM", total_spam)
    col3.metric("🌐 Total URL", total_urls)
    col4.metric("☠ URL Berbahaya", total_malicious_urls)

    st.markdown("---")

    # ===== Grafik =====
    plt.style.use("seaborn-v0_8-muted")

    colA, colB = st.columns(2)

    # Grafik Pie SPAM vs Legit
    with colA:
        st.subheader("📊 Proporsi SPAM vs Legit")
        fig1, ax1 = plt.subplots()
        labels = ["SPAM", "Legit"]
        sizes = [total_spam, total_email - total_spam]
        colors = ["#e74c3c", "#2ecc71"]
        wedges, texts, autotexts = ax1.pie(
            sizes,
            labels=labels,
            autopct="%1.1f%%",
            startangle=90,
            colors=colors,
            textprops={"color": "white", "weight": "bold"},
        )
        ax1.set_title("Distribusi Email Berdasarkan Klasifikasi", fontsize=12)
        ax1.axis("equal")
        st.pyplot(fig1)

    # Grafik URL Berbahaya per Email
    with colB:
        st.subheader("☠ Distribusi URL Berbahaya per Email")
        if malicious_per_email:
            df_mal = pd.DataFrame(malicious_per_email)
            fig2, ax2 = plt.subplots(figsize=(8, 4))
            bars = ax2.bar(df_mal["email"], df_mal["malicious_count"], color="#e74c3c")
            ax2.set_xlabel("Email", fontsize=10)
            ax2.set_ylabel("Jumlah URL Berbahaya", fontsize=10)
            ax2.set_title("Jumlah URL Berbahaya per Email", fontsize=12)
            ax2.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
            plt.xticks(rotation=45, ha="right")
            plt.grid(axis="y", linestyle="--", alpha=0.6)
            st.pyplot(fig2)
        else:
            st.info("Tidak ada URL berbahaya yang terdeteksi.")

# ================== Halaman TENTANG ==================
else:
    st.title("ℹ Tentang Aplikasi")
    st.markdown(
        """
    **📧 Phishing Email Analyzer Dashboard**  
    Versi modern dari dashboard Streamlit untuk analisis email phishing.

    **Fitur utama:**
    - Deteksi SPAM via SpamAssassin  
    - Analisis URL dengan VirusTotal  
    - Statistik global dengan grafik profesional  
    - Navigasi multi-halaman  
    - Desain bersih dan responsif  

    💡 *Dibuat untuk memudahkan investigasi email mencurigakan secara cepat & terstruktur.*
    """
    )
