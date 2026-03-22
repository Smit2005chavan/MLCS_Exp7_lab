"""
Malicious URL Dataset Scraper
==============================
Experiment 7 - MLCS | Roll No: 16014223080

pip install requests pandas openpyxl tqdm
python url_scraper.py
"""

import requests
import pandas as pd
import io
import zipfile
import csv
import time
import os
import sys
import traceback

# ─── CONFIG ───────────────────────────────────────────────────────────────────

MAX_PER_CLASS    = 3000           # URLs per class (raise if needed)
BALANCE_STRATEGY = "undersample"  # "undersample" | "oversample"
OUTPUT_DIR       = os.path.dirname(os.path.abspath(_file_))  # same folder as script
OUTPUT_RAW       = os.path.join(OUTPUT_DIR, "urls_raw.xlsx")
OUTPUT_BALANCED  = os.path.join(OUTPUT_DIR, "urls_balanced.xlsx")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
    )
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def log(msg): print(msg, flush=True)

def safe_get(url, timeout=45, **kwargs):
    """requests.get with full error printing."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except requests.exceptions.ConnectionError:
        print(f"  [FAIL] Cannot connect to {url} — check internet/firewall", flush=True)
    except requests.exceptions.Timeout:
        print(f"  [FAIL] Timeout: {url}", flush=True)
    except requests.exceptions.HTTPError as e:
        print(f"  [FAIL] HTTP {e.response.status_code}: {url}", flush=True)
    except Exception as e:
        print(f"  [FAIL] {url} -> {e}", flush=True)
    return None

# ─── MALICIOUS SOURCES ────────────────────────────────────────────────────────

def scrape_urlhaus_recent():
    log("  [URLhaus recent] Fetching...")
    r = safe_get("https://urlhaus.abuse.ch/downloads/csv_recent/")
    if not r:
        return []
    lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
    try:
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        records = []
        for row in reader:
            u = (row.get("url") or row.get('"url"') or "").strip().strip('"')
            threat = (row.get("threat") or "malware").strip() or "malware"
            if u.startswith("http"):
                records.append({"url": u, "label": 1, "source": "urlhaus", "type": threat})
        log(f"  [URLhaus recent] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [URLhaus recent] Parse error: {e}", flush=True)
        return []


def scrape_urlhaus_full():
    log("  [URLhaus full ZIP] Fetching...")
    r = safe_get("https://urlhaus.abuse.ch/downloads/csv/", timeout=90)
    if not r:
        return []
    try:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
        with z.open(csv_name) as f:
            raw = f.read().decode("utf-8", errors="ignore")
        lines = [l for l in raw.splitlines() if not l.startswith("#") and l.strip()]
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        records = []
        for row in reader:
            u = (row.get("url") or "").strip().strip('"')
            threat = (row.get("threat") or "malware").strip() or "malware"
            if u.startswith("http"):
                records.append({"url": u, "label": 1, "source": "urlhaus_full", "type": threat})
        log(f"  [URLhaus full] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [URLhaus full] Parse error: {e}", flush=True)
        return []


def scrape_openphish():
    log("  [OpenPhish] Fetching...")
    r = safe_get("https://openphish.com/feed.txt")
    if not r:
        return []
    records = [
        {"url": l.strip(), "label": 1, "source": "openphish", "type": "phishing"}
        for l in r.text.splitlines() if l.strip().startswith("http")
    ]
    log(f"  [OpenPhish] {len(records)} URLs")
    return records


def scrape_phishtank():
    log("  [PhishTank] Fetching...")
    r = safe_get("http://data.phishtank.com/data/online-valid.csv", timeout=90)
    if not r:
        return []
    try:
        df = pd.read_csv(io.StringIO(r.text))
        col = next((c for c in df.columns if "url" in c.lower()), None)
        if col is None:
            print("  [PhishTank] No URL column found", flush=True)
            return []
        records = []
        for u in df[col].dropna():
            u = str(u).strip()
            if u.startswith("http"):
                records.append({"url": u, "label": 1, "source": "phishtank", "type": "phishing"})
        log(f"  [PhishTank] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [PhishTank] Parse error: {e}", flush=True)
        return []


def scrape_cybercrime_tracker():
    log("  [Cybercrime Tracker] Fetching...")
    r = safe_get("https://cybercrime-tracker.net/all.php")
    if not r:
        return []
    records = []
    for line in r.text.splitlines():
        u = line.strip()
        if u.startswith("http"):
            records.append({"url": u, "label": 1, "source": "cybercrime_tracker", "type": "c2"})
    log(f"  [Cybercrime Tracker] {len(records)} URLs")
    return records


# ─── BENIGN SOURCES ───────────────────────────────────────────────────────────

def scrape_tranco(n=8000):
    log("  [Tranco] Fetching...")
    r = safe_get("https://tranco-list.eu/download/recent/1000000", timeout=90)
    if not r:
        return []
    try:
        if r.content[:2] == b'PK':
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                content = f.read().decode("utf-8", errors="ignore")
        else:
            content = r.text

        records = []
        for i, line in enumerate(content.splitlines()):
            if i >= n:
                break
            parts = line.strip().split(",")
            domain = parts[-1].strip() if parts else ""
            if domain and "." in domain:
                records.append({"url": f"https://{domain}", "label": 0, "source": "tranco", "type": "benign"})
        log(f"  [Tranco] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [Tranco] Parse error: {e}", flush=True)
        return []


def scrape_majestic(n=8000):
    log("  [Majestic Million] Fetching...")
    r = safe_get("https://downloads.majestic.com/majestic_million.csv", timeout=90)
    if not r:
        return []
    try:
        df = pd.read_csv(io.StringIO(r.text), nrows=n)
        col = next((c for c in df.columns if "domain" in c.lower()), None)
        if col is None:
            print("  [Majestic] No Domain column found", flush=True)
            return []
        records = [
            {"url": f"https://{str(d).strip()}", "label": 0, "source": "majestic", "type": "benign"}
            for d in df[col].dropna() if "." in str(d)
        ]
        log(f"  [Majestic] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [Majestic] Parse error: {e}", flush=True)
        return []


def scrape_umbrella(n=8000):
    log("  [Cisco Umbrella] Fetching...")
    r = safe_get("https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", timeout=90)
    if not r:
        return []
    try:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        with z.open(z.namelist()[0]) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            records = []
            for i, row in enumerate(reader):
                if i >= n:
                    break
                if len(row) >= 2 and "." in row[1]:
                    records.append({"url": f"https://{row[1].strip()}", "label": 0, "source": "umbrella", "type": "benign"})
        log(f"  [Umbrella] {len(records)} URLs")
        return records
    except Exception as e:
        print(f"  [Umbrella] Parse error: {e}", flush=True)
        return []


# ─── FALLBACK SEED DATA ───────────────────────────────────────────────────────
# Written to Excel even if all scrapers fail, so you always get a file.

FALLBACK_MALICIOUS = [
    {"url": "http://malware-test.phishing-example.xyz/payload.exe",   "label": 1, "source": "fallback", "type": "malware"},
    {"url": "http://192.168.100.1/admin/login.php?redirect=evil",      "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://free-iphone-winner.tk/claim?id=123456",            "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://secure-paypa1.com/verify/account",                 "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://update-flash-player.info/setup.exe",               "label": 1, "source": "fallback", "type": "malware"},
    {"url": "http://login.amazon-secureinfo.com/signin",               "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://dropbox-file-share.ru/download/doc.exe",           "label": 1, "source": "fallback", "type": "malware"},
    {"url": "http://verify-yourpaypal.com/confirm?user=victim",        "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://bank0famerica.phish.biz/secure/login",             "label": 1, "source": "fallback", "type": "phishing"},
    {"url": "http://bit.ly/malware-download-test-abc123",              "label": 1, "source": "fallback", "type": "malware"},
]

FALLBACK_BENIGN = [
    {"url": "https://www.google.com",          "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.wikipedia.org",       "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.github.com",          "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.microsoft.com",       "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.stackoverflow.com",   "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.amazon.com",          "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.youtube.com",         "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.linkedin.com",        "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.nytimes.com",         "label": 0, "source": "fallback", "type": "benign"},
    {"url": "https://www.bbc.com",             "label": 0, "source": "fallback", "type": "benign"},
]

# ─── COLLECT ─────────────────────────────────────────────────────────────────

def collect_all():
    all_records = []

    log("\n-- MALICIOUS SOURCES --")
    all_records += scrape_urlhaus_recent();     time.sleep(1)
    all_records += scrape_openphish();          time.sleep(1)
    all_records += scrape_phishtank();          time.sleep(1)
    all_records += scrape_cybercrime_tracker(); time.sleep(1)

    mal_count = sum(1 for r in all_records if r["label"] == 1)
    log(f"  -> Malicious collected so far: {mal_count}")
    if mal_count < MAX_PER_CLASS:
        all_records += scrape_urlhaus_full()
        time.sleep(1)

    log("\n-- BENIGN SOURCES --")
    all_records += scrape_tranco(MAX_PER_CLASS * 3);   time.sleep(1)
    all_records += scrape_majestic(MAX_PER_CLASS * 3); time.sleep(1)
    all_records += scrape_umbrella(MAX_PER_CLASS * 3)

    df = pd.DataFrame(all_records) if all_records else pd.DataFrame(columns=["url","label","source","type"])

    # Check we have both classes
    if df.empty or df["label"].nunique() < 2:
        log("\n  [WARN] Scrapers returned no/insufficient data.")
        log("         Using fallback seed data so Excel is still written.")
        log("         Re-run with a working internet connection for real URLs.")
        df = pd.DataFrame(FALLBACK_MALICIOUS + FALLBACK_BENIGN)
    else:
        # Merge fallback into real data just to pad if one class is tiny
        mal = df[df["label"] == 1]
        ben = df[df["label"] == 0]
        if len(mal) == 0:
            df = pd.concat([df, pd.DataFrame(FALLBACK_MALICIOUS)], ignore_index=True)
        if len(ben) == 0:
            df = pd.concat([df, pd.DataFrame(FALLBACK_BENIGN)], ignore_index=True)

    before = len(df)
    df = df.drop_duplicates(subset="url").reset_index(drop=True)
    log(f"\n  Deduplicated: {before} -> {len(df)} rows")
    return df

# ─── BALANCE ─────────────────────────────────────────────────────────────────

def balance_dataset(df):
    mal = df[df["label"] == 1]
    ben = df[df["label"] == 0]

    log(f"\n-- BALANCING ({BALANCE_STRATEGY}) --")
    log(f"  Before -> Malicious: {len(mal)}, Benign: {len(ben)}")

    n_mal = min(len(mal), MAX_PER_CLASS)
    n_ben = min(len(ben), MAX_PER_CLASS)

    if BALANCE_STRATEGY == "undersample":
        target = min(n_mal, n_ben)
        mal_b  = mal.sample(n=target, random_state=42)
        ben_b  = ben.sample(n=target, random_state=42)

    elif BALANCE_STRATEGY == "oversample":
        target = max(n_mal, n_ben)
        mal_b  = mal.sample(n=target, replace=(n_mal < target), random_state=42)
        ben_b  = ben.sample(n=target, replace=(n_ben < target), random_state=42)
    else:
        raise ValueError(f"Unknown BALANCE_STRATEGY: {BALANCE_STRATEGY}")

    balanced = (
        pd.concat([mal_b, ben_b])
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )
    log(f"  After  -> Total: {len(balanced)} | Per class: {target}")
    return balanced

# ─── EXPORT ──────────────────────────────────────────────────────────────────

def export_excel(df, path, sheet_name="URLs"):
    try:
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name=sheet_name)

            summary = (
                df.groupby(["label", "source", "type"])
                .size()
                .reset_index(name="count")
            )
            summary.insert(0, "label_name", summary["label"].map({0: "Benign", 1: "Malicious"}))
            summary.to_excel(writer, index=False, sheet_name="Summary")

        log(f"  OK Saved: {path}")
        return True
    except PermissionError:
        print(f"\n  [ERROR] Cannot write {path}", flush=True)
        print(f"          Is the file already open in Excel? Close it and retry.", flush=True)
        return False
    except Exception as e:
        print(f"\n  [ERROR] Failed to write {path}: {e}", flush=True)
        traceback.print_exc()
        return False

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    log("=" * 55)
    log("  URL Scraper -- MLCS Exp 7")
    log(f"  Output dir : {OUTPUT_DIR}")
    log("=" * 55)

    try:
        import openpyxl
    except ImportError:
        print("\n[ERROR] openpyxl not installed.", flush=True)
        print("Run: pip install openpyxl", flush=True)
        sys.exit(1)

    # 1. Scrape
    df_raw = collect_all()
    log(f"\n-- RAW DATASET --")
    log(f"  Total rows : {len(df_raw)}")
    log(f"  Labels     :\n{df_raw['label'].value_counts().to_string()}")
    export_excel(df_raw, OUTPUT_RAW, sheet_name="All URLs")

    # 2. Balance
    df_bal = balance_dataset(df_raw)
    log(f"\n-- BALANCED DATASET --")
    log(f"  Total rows : {len(df_bal)}")
    log(f"  Labels     :\n{df_bal['label'].value_counts().to_string()}")
    export_excel(df_bal, OUTPUT_BALANCED, sheet_name="Balanced URLs")

    log("\n" + "=" * 55)
    log("  DONE")
    log(f"  {OUTPUT_RAW}")
    log(f"  {OUTPUT_BALANCED}")
    log("=" * 55)


if _name_ == "_main_":
    main()
