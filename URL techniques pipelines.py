"""
MLCS Experiment 7 — Malicious URL Detection
=============================================
Roll No : 16014223080
Batch   : A2

Steps covered:
  2. Data Preprocessing
  3. Feature Extraction
  4. Model Selection
  5. Model Training & Evaluation
  6. Prediction on New URLs

Input  : urls_balanced.xlsx  (keep in same folder as this script)
Output : mlcs_exp7_full_pipeline.xlsx

Install deps:
  pip install scikit-learn pandas openpyxl
"""

import os
import re
import warnings
import pandas as pd
import numpy as np
from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report
)
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ─── PATHS ────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = os.path.dirname(os.path.abspath(_file_))
INPUT_FILE   = os.path.join(SCRIPT_DIR, "urls_balanced.xlsx")
OUTPUT_FILE  = os.path.join(SCRIPT_DIR, "mlcs_exp7_full_pipeline.xlsx")

def log(msg): print(msg, flush=True)

# ─── STEP 2: DATA PREPROCESSING ───────────────────────────────────────────────

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    log("\n[STEP 2] Preprocessing...")

    before = len(df)
    df = df.drop_duplicates(subset="url")
    df = df.dropna(subset=["url", "label"])
    df["url"]   = df["url"].str.strip()
    df           = df[df["url"].str.startswith("http")]   # remove non-URL garbage
    df["label"] = df["label"].astype(int)
    df           = df.reset_index(drop=True)

    log(f"  Rows before : {before}")
    log(f"  Rows after  : {len(df)}")
    log(f"  Class dist  : {df['label'].value_counts().to_dict()}")
    return df

# ─── STEP 3: FEATURE EXTRACTION ───────────────────────────────────────────────

# Known suspicious TLDs and URL shorteners
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                   ".ru", ".cc", ".biz", ".info", ".top", ".pw"}
SHORTENERS      = {"bit.ly", "goo.gl", "tinyurl.com", "t.co",
                   "ow.ly", "qrco.de", "rb.gy", "is.gd", "short.io"}

def extract_features(url: str) -> dict:
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        query    = parsed.query or ""
        tld      = "." + hostname.split(".")[-1] if "." in hostname else ""

        return {
            # --- Length-based ---
            "url_length":           len(url),
            "hostname_length":      len(hostname),
            "path_length":          len(path),
            "query_length":         len(query),
            # --- Count-based ---
            "num_dots":             url.count("."),
            "num_hyphens":          url.count("-"),
            "num_underscores":      url.count("_"),
            "num_slashes":          url.count("/"),
            "num_digits":           sum(c.isdigit() for c in url),
            "num_query_params":     len(query.split("&")) if query else 0,
            "num_subdomains":       max(len(hostname.split(".")) - 2, 0),
            "num_special_chars":    len(re.findall(r"[^a-zA-Z0-9./:?=&_\-]", url)),
            # --- Binary flags ---
            "has_https":            int(url.startswith("https")),
            "has_at_symbol":        int("@" in url),
            "has_double_slash":     int("//" in url[7:]),
            "has_ip_address":       int(bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url))),
            "has_port":             int(bool(parsed.port)),
            "has_suspicious_tld":   int(tld.lower() in SUSPICIOUS_TLDS),
            "is_url_shortener":     int(hostname.lower() in SHORTENERS),
            "has_hex_encoding":     int("%" in url),
            "has_suspicious_words": int(bool(re.search(
                r"login|verify|secure|update|account|confirm|banking|"
                r"paypal|signin|password|credential|webflow|gitbook",
                url, re.I
            ))),
            # --- Ratio-based ---
            "digit_ratio":          sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_char_ratio":   len(re.findall(r"[^a-zA-Z0-9]", url)) / max(len(url), 1),
        }
    except Exception:
        return {k: 0 for k in [
            "url_length", "hostname_length", "path_length", "query_length",
            "num_dots", "num_hyphens", "num_underscores", "num_slashes",
            "num_digits", "num_query_params", "num_subdomains", "num_special_chars",
            "has_https", "has_at_symbol", "has_double_slash", "has_ip_address",
            "has_port", "has_suspicious_tld", "is_url_shortener", "has_hex_encoding",
            "has_suspicious_words", "digit_ratio", "special_char_ratio",
        ]}


def build_feature_matrix(df: pd.DataFrame):
    log("\n[STEP 3] Extracting features...")
    X = pd.DataFrame(df["url"].apply(extract_features).tolist())
    y = df["label"].reset_index(drop=True)
    log(f"  Feature matrix : {X.shape}")
    log(f"  Features       : {X.columns.tolist()}")
    return X, y

# ─── STEPS 4 & 5: MODEL TRAINING & EVALUATION ────────────────────────────────

def train_and_evaluate(X: pd.DataFrame, y: pd.Series):
    log("\n[STEP 4 & 5] Training & Evaluating Models...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler      = StandardScaler()
    X_train_sc  = scaler.fit_transform(X_train)
    X_test_sc   = scaler.transform(X_test)

    # Models that need scaled input
    NEEDS_SCALE = {"Logistic Regression", "SVM"}

    models = {
        "Random Forest":       RandomForestClassifier(n_estimators=100, random_state=42),
        "Gradient Boosting":   GradientBoostingClassifier(n_estimators=100, random_state=42),
        "Decision Tree":       DecisionTreeClassifier(random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "SVM":                 SVC(probability=True, random_state=42),
    }

    results  = []
    reports  = {}
    cms      = {}
    trained  = {}

    for name, model in models.items():
        Xtr = X_train_sc if name in NEEDS_SCALE else X_train.values
        Xte = X_test_sc  if name in NEEDS_SCALE else X_test.values

        model.fit(Xtr, y_train)
        y_pred = model.predict(Xte)
        y_prob = model.predict_proba(Xte)[:, 1]

        cv = cross_val_score(
            model, Xtr, y_train,
            cv=StratifiedKFold(5), scoring="accuracy"
        )

        row = {
            "Model":        name,
            "Accuracy (%)": round(accuracy_score(y_test, y_pred) * 100, 2),
            "Precision (%)":round(precision_score(y_test, y_pred) * 100, 2),
            "Recall (%)":   round(recall_score(y_test, y_pred) * 100, 2),
            "F1-Score (%)": round(f1_score(y_test, y_pred) * 100, 2),
            "ROC-AUC (%)":  round(roc_auc_score(y_test, y_prob) * 100, 2),
            "CV Mean (%)":  round(cv.mean() * 100, 2),
            "CV Std (%)":   round(cv.std() * 100, 2),
        }
        results.append(row)
        reports[name] = classification_report(
            y_test, y_pred, target_names=["Benign", "Malicious"]
        )
        cm = confusion_matrix(y_test, y_pred)
        cms[name] = pd.DataFrame(
            cm,
            index=["Actual Benign", "Actual Malicious"],
            columns=["Predicted Benign", "Predicted Malicious"]
        )
        trained[name] = model

        log(f"  [{name:22s}]  Acc={row['Accuracy (%)']:6.2f}%  "
            f"F1={row['F1-Score (%)']:6.2f}%  AUC={row['ROC-AUC (%)']:6.2f}%")

    results_df = pd.DataFrame(results).sort_values("F1-Score (%)", ascending=False)
    return results_df, reports, cms, trained, scaler, X_test, y_test

# ─── STEP 6: PREDICT ON NEW URLs ─────────────────────────────────────────────

def predict_new_urls(trained_models: dict, scaler, best_model_name: str):
    log(f"\n[STEP 6] Predicting new URLs with best model: {best_model_name}")

    new_urls = [
        # --- Obviously Benign ---
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.microsoft.com/en-us/security",
        "https://stackoverflow.com/questions/12345",
        # --- Obviously Malicious ---
        "http://verify-paypal-account.tk/login?user=victim",
        "http://free-bitcoin-winner.xyz/claim?id=99999&ref=abc",
        "http://192.168.1.1/admin/update.php?redirect=evil",
        "http://secure-bankofamerica.phishing.biz/verify",
        # --- Ambiguous ---
        "https://github.com/torvalds/linux",
        "http://bit.ly/3xEvIl-phish",
        "http://swissborg-logine.webflow.io/",
        "https://support-microsoft-help.com/security/update",
    ]

    best_model  = trained_models[best_model_name]
    NEEDS_SCALE = {"Logistic Regression", "SVM"}
    feats       = pd.DataFrame([extract_features(u) for u in new_urls])
    X_in        = scaler.transform(feats) if best_model_name in NEEDS_SCALE else feats.values

    preds = best_model.predict(X_in)
    probs = best_model.predict_proba(X_in)[:, 1]

    pred_df = pd.DataFrame({
        "URL":              new_urls,
        "Prediction":       ["Malicious" if p == 1 else "Benign" for p in preds],
        "Predicted Label":  preds,
        "Confidence (%)":   [
            round(prob * 100, 2) if pred == 1 else round((1 - prob) * 100, 2)
            for prob, pred in zip(probs, preds)
        ],
    })

    log(pred_df.to_string(index=False))
    return pred_df

# ─── EXPORT EXCEL ─────────────────────────────────────────────────────────────

def export_excel(df_clean, X, y, results_df, reports, cms, pred_df, trained):
    log(f"\n[EXPORT] Writing Excel → {OUTPUT_FILE}")

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:

        # Sheet 1 — Preprocessed data
        out = df_clean[["url", "label", "source", "type"]].copy()
        out["label_name"] = out["label"].map({0: "Benign", 1: "Malicious"})
        out.to_excel(writer, index=False, sheet_name="1_Preprocessed_Data")

        # Sheet 2 — Feature matrix
        feat_export = X.copy()
        feat_export.insert(0, "url", df_clean["url"].values)
        feat_export["label"] = y.values
        feat_export["label_name"] = feat_export["label"].map({0: "Benign", 1: "Malicious"})
        feat_export.to_excel(writer, index=False, sheet_name="2_Feature_Matrix")

        # Sheet 3 — Model comparison
        results_df.to_excel(writer, index=False, sheet_name="3_Model_Comparison")

        # Sheet 4 — Classification reports
        rows = []
        for name, rep in reports.items():
            rows.append({"Model": name, "Report": rep})
        pd.DataFrame(rows).to_excel(writer, index=False, sheet_name="4_Classification_Reports")

        # Sheet 5 — Confusion matrices (stacked)
        cm_rows = []
        for name, cm_df in cms.items():
            cm_rows.append({"": f"=== {name} ==="})
            for idx_label, row in cm_df.iterrows():
                cm_rows.append({"": idx_label, **row.to_dict()})
            cm_rows.append({})  # blank spacer
        pd.DataFrame(cm_rows).to_excel(writer, index=False, sheet_name="5_Confusion_Matrices")

        # Sheet 6 — New URL predictions
        pred_df.to_excel(writer, index=False, sheet_name="6_New_URL_Predictions")

        # Sheet 7 — Feature importance (Random Forest)
        rf = trained.get("Random Forest")
        if rf:
            fi = pd.DataFrame({
                "Feature":    X.columns,
                "Importance": rf.feature_importances_,
            }).sort_values("Importance", ascending=False).reset_index(drop=True)
            fi["Rank"] = fi.index + 1
            fi[["Rank", "Feature", "Importance"]].to_excel(
                writer, index=False, sheet_name="7_Feature_Importance"
            )

    log(f"  Saved: {OUTPUT_FILE}")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  MLCS Exp 7 — Malicious URL Detection Pipeline")
    log("=" * 60)

    # Load
    if not os.path.exists(INPUT_FILE):
        print(f"\n[ERROR] Input file not found: {INPUT_FILE}")
        print("        Place urls_balanced.xlsx in the same folder as this script.")
        return

    df_raw = pd.read_excel(INPUT_FILE)
    log(f"\n  Loaded: {INPUT_FILE}  ({df_raw.shape[0]} rows)")

    # Pipeline
    df_clean            = preprocess(df_raw)
    X, y                = build_feature_matrix(df_clean)
    results_df, reports, cms, trained, scaler, X_test, y_test = train_and_evaluate(X, y)

    best_model_name     = results_df.iloc[0]["Model"]
    log(f"\n  Best model: {best_model_name}")

    pred_df             = predict_new_urls(trained, scaler, best_model_name)

    export_excel(df_clean, X, y, results_df, reports, cms, pred_df, trained)

    log("\n" + "=" * 60)
    log("  DONE — open mlcs_exp7_full_pipeline.xlsx")
    log("=" * 60)

if _name_ == "_main_":
    main()
