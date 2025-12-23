#!/usr/bin/env python3
"""
Single-file phishing analyzer (versi tanpa attachment):
- Parsing .eml tanpa attachment
- Analisis SpamAssassin
- Analisis URL ke VirusTotal (dengan polling status queued/in-progress/completed)
- Normalisasi URL sebelum cek cache / submit VT
- Cache hasil VT
- Simpan hasil ke reports/report_final.json
"""

import os
import re
import json
import time
import glob
import shutil
import subprocess
import html
import requests
from urllib.parse import urlparse, urlunparse
from dotenv import load_dotenv
from mailparser import parse_from_file

# ---------------- CONFIG ----------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

DATA_DIR = "data"
CACHE_DIR = "cache"
REPORT_DIR = "reports"

CACHE_FILE = os.path.join(CACHE_DIR, "cache_vt.json")
REPORT_FILE = os.path.join(REPORT_DIR, "report_final.json")
URL_REGEX = r"https?://[^\s'\"<>)+]+"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# ---------------- Cache ----------------
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

cache = load_cache()

# ---------------- Helpers ----------------
def run_subprocess(cmd, input_bytes=None, timeout=30):
    try:
        proc = subprocess.run(cmd, input=input_bytes, capture_output=True, timeout=timeout)
        stdout = proc.stdout.decode(errors="ignore") if proc.stdout else ""
        stderr = proc.stderr.decode(errors="ignore") if proc.stderr else ""
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"

# ---------------- URL Normalization ----------------
def normalize_url(raw_url: str) -> str:
    decoded = html.unescape(raw_url).strip().strip('"').strip("'")
    parsed = urlparse(decoded)
    return urlunparse(parsed)

# ---------------- VirusTotal (URL Only) ----------------
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/{}"

def vt_analyze_url(url, cache, max_poll=3, poll_delay=10):
    """Submit URL ke VT, polling sampai status completed."""
    normalized_url = normalize_url(url)
    if normalized_url in cache:
        return cache[normalized_url]

    if not VT_API_KEY:
        return {"url": normalized_url, "info": "No VT API key configured"}

    try:
        # Submit URL
        r = requests.post(VT_URL_SCAN, headers=HEADERS, data={"url": normalized_url}, timeout=15)
        if r.status_code not in (200, 201, 202):
            return {"url": normalized_url, "info": f"VT submit error {r.status_code}"}

        analysis_id = r.json().get("data", {}).get("id")
        if not analysis_id:
            return {"url": normalized_url, "info": "VT returned no analysis id"}

        print(f"[VT] Analisis URL dikirim: {normalized_url}")

        # Polling hasil
        analysis_url = VT_ANALYSIS.format(analysis_id)
        for i in range(max_poll):
            rr = requests.get(analysis_url, headers=HEADERS, timeout=15)
            if rr.status_code != 200:
                print(f"[VT] Polling gagal ({rr.status_code}) {normalized_url}")
                time.sleep(poll_delay)
                continue

            data = rr.json()
            attrs = data.get("data", {}).get("attributes", {}) or {}
            status = attrs.get("status")
            stats = attrs.get("stats") or attrs.get("last_analysis_stats") or {}

            print(f" ⏳ [URL VT] {normalized_url} status={status} ({i+1}/{max_poll})")

            if status == "completed":
                out = {"url": normalized_url, "status": status, "vt_stats": stats}
                cache[normalized_url] = out
                save_cache(cache)
                return out

            time.sleep(poll_delay)

        return {"url": normalized_url, "status": status, "info": "VT: no result after max polling"}

    except Exception as e:
        return {"url": normalized_url, "info": f"VT error: {e}"}

# ---------------- SpamAssassin Parsing ----------------
SPAM_HEADER_REGEX = re.compile(
    r"X-Spam-Status:\s*(Yes|No),\s*score=([\d\.\-]+).*?tests=([A-Z0-9_, ]+)",
    re.IGNORECASE | re.DOTALL,
)

def parse_spamassassin_output_text(text):
    result = {"is_spam": None, "score": None, "tests": [], "full_report": text}
    m = SPAM_HEADER_REGEX.search(text)
    if m:
        result["is_spam"] = (m.group(1).lower() == "yes")
        result["score"] = float(m.group(2))
        result["tests"] = [t.strip() for t in re.split(r"[,_\s]+", m.group(3)) if t.strip()]
        return result

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines:
        m2 = re.match(r"^([0-9\.\-]+)/([0-9\.\-]+)", lines[0])
        if m2:
            score = float(m2.group(1))
            threshold = float(m2.group(2))
            is_spam = score >= threshold
            tests = []
            for ln in lines[1:]:
                m_rule = re.match(r"^-?\d+(\.\d+)?\s+([A-Z0-9_]+)\b", ln)
                if m_rule:
                    tests.append(m_rule.group(2))
            result.update({"is_spam": is_spam, "score": score, "tests": tests})
    return result

def check_spamassassin_cli(eml_path):
    with open(eml_path, "rb") as f:
        data = f.read()

    spamc = shutil.which("spamc")
    if spamc:
        code, out, err = run_subprocess([spamc, "-R"], input_bytes=data)
        if code == 0 and out:
            parsed = parse_spamassassin_output_text(out)
            parsed["method"] = "spamc"
            return parsed

    spamassassin = shutil.which("spamassassin")
    if spamassassin:
        code, out, err = run_subprocess([spamassassin, "-t"], input_bytes=data)
        if (code in [0, 2]) and out:
            parsed = parse_spamassassin_output_text(out)
            parsed["method"] = "spamassassin"
            return parsed

    return {"info": "spamc/spamassassin not found or failed"}

# ---------------- Email Analyzer ----------------
def analyze_email(file_path, cache):
    res = {
        "file_name": os.path.basename(file_path),
        "headers": {},
        "urls": [],
        "vt_url_analysis": [],
        "spamassassin": {},
    }

    try:
        mail = parse_from_file(file_path)
        res["headers"] = {
            "from": mail.from_[0][1] if mail.from_ else None,
            "to": mail.to[0][1] if mail.to else None,
            "subject": mail.subject,
            "date": mail.date.isoformat() if mail.date else None,
            "received": mail.headers.get("Received"),
        }

        # URLs (tanpa attachment)
        combined_text = (mail.body or "") + " " + " ".join(mail.text_html or [])
        urls = list(set(re.findall(URL_REGEX, combined_text)))
        res["urls"] = urls

        for u in urls:
            vt_u = vt_analyze_url(u, cache)
            res["vt_url_analysis"].append(vt_u)

        # SpamAssassin
        sa = check_spamassassin_cli(file_path)
        res["spamassassin"] = sa

    except Exception as e:
        res["error"] = str(e)

    return res

# ---------------- Main ----------------
def main():
    global cache
    cache = load_cache()
    eml_files = glob.glob(os.path.join(DATA_DIR, "*.eml"))
    if not eml_files:
        print(f"Tidak ada file .eml di folder '{DATA_DIR}'.")
        return

    report = []
    for p in eml_files:
        print(f"\n=== Analisis email: {os.path.basename(p)} ===")
        r = analyze_email(p, cache)
        sa = r.get("spamassassin", {})
        if sa.get("score") is not None:
            print(f" SpamAssassin → score={sa['score']} | spam={sa['is_spam']} | rules={sa.get('tests')}")
        report.append(r)

    save_cache(cache)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Analisis selesai. Laporan: {REPORT_FILE}")

if __name__ == "__main__":
    main()
