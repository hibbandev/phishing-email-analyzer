# 📧 Phishing Email Analyzer (SOC Portfolio)

A practical **email phishing analysis tool** built with Python, designed
to demonstrate **SOC / Blue Team** skills such as email forensics, spam
analysis, and threat intelligence enrichment.

This project combines **SpamAssassin**, **VirusTotal API**, and an
interactive **Streamlit dashboard** to support structured investigation
of suspicious email samples.

------------------------------------------------------------------------

## 🎯 Project Goals

-   Demonstrate hands-on SOC workflow for phishing email analysis
-   Automate spam scoring and URL reputation checking
-   Present investigation results in a clear, analyst-friendly dashboard
-   Provide a reproducible and extensible analysis pipeline

------------------------------------------------------------------------

## 🛠️ Key Features

-   📥 Parse raw email files (`.eml`)
-   🧠 Spam detection using **SpamAssassin** (CLI-based)
-   🌐 URL extraction and reputation analysis via **VirusTotal API v3**
-   🔄 Polling mechanism for VirusTotal analysis status
-   💾 URL-based caching to reduce API quota usage
-   📄 Structured JSON report output
-   📊 Streamlit dashboard with:
    -   Email-level investigation view
    -   URL status table (Malicious / Suspicious / Harmless)
    -   Global statistics and visual summaries

------------------------------------------------------------------------

## 📂 Project Structure

    phishing-email-analyzer/
    ├── analyzer.py          # Email analysis engine
    ├── app.py               # Streamlit dashboard
    ├── data/                # Input .eml samples
    ├── cache/               # VirusTotal cache (ignored in git)
    ├── reports/             # Analysis results (ignored in git)
    ├── requirements.txt
    └── README.md

------------------------------------------------------------------------

## ⚙️ Requirements

### Python

-   Python **3.8+**

### System Dependencies

-   One of the following:
    -   `spamassassin`
    -   `spamc`

Example (Debian/Ubuntu):

``` bash
sudo apt install spamassassin spamc
```

### Python Dependencies

``` bash
pip install -r requirements.txt
```

Minimal dependencies:

    streamlit
    pandas
    matplotlib
    requests
    mailparser
    python-dotenv

------------------------------------------------------------------------

## 🔑 VirusTotal Configuration

Create a `.env` file in the project root:

    VT_API_KEY=YOUR_API_KEY_HERE

> ⚠️ Do **not** commit `.env`, cache files, or reports to public
> repositories.

------------------------------------------------------------------------

## ▶️ Usage

### 1️⃣ Prepare Email Samples

Place `.eml` files inside the `data/` directory.

### 2️⃣ Run Email Analysis

``` bash
python analyzer.py
```

This step will: - Parse email headers and body - Run SpamAssassin
scoring - Extract URLs - Submit URLs to VirusTotal and poll results -
Save structured output to `reports/report_final.json`

### 3️⃣ Launch Dashboard

``` bash
streamlit run app.py
```

Open your browser at:

    http://localhost:8501

------------------------------------------------------------------------

## 📊 Dashboard Overview

### 🔍 Email Investigation View

-   Sender, recipient, subject, and date
-   SpamAssassin score and triggered rules
-   URL table with VirusTotal verdicts

### 📈 Statistics View

-   Total analyzed emails
-   Spam vs legitimate distribution
-   Number of malicious URLs per email
-   Visual charts for quick situational awareness

------------------------------------------------------------------------

## 🧪 Detection Logic Notes

-   Spam classification primarily follows SpamAssassin scoring

-   URLs are flagged as **malicious** when:

        vt_stats.malicious > 0

-   Each URL is counted once regardless of the number of AV detections

Results are **indicative**, not authoritative, and should support ---
not replace --- analyst judgment.

------------------------------------------------------------------------

## ⚠️ Limitations

-   Attachment analysis is not included
-   Depends on third-party reputation services
-   Designed for offline / sample-based analysis (not real-time email
    gateway)

------------------------------------------------------------------------

## 🔐 Security & Ethics

This project is intended for: - Security research - SOC training and
learning - Defensive security analysis

❌ Do not use for unauthorized testing or malicious activities.

------------------------------------------------------------------------

## 👤 Author

**Ibnu Hibban Dzulfikri**\
Security Operations / Blue Team Portfolio Project

------------------------------------------------------------------------

## ⭐ Future Improvements (Optional)

-   Attachment sandboxing
-   IOC export (CSV / STIX)
-   Email authentication checks (SPF, DKIM, DMARC)
-   SIEM integration

------------------------------------------------------------------------

If you are a recruiter, SOC analyst, or security engineer reviewing this
repository: **thank you for your time and feedback.**
