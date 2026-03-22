# MLCS Experiment 7 — Malicious URL Detection

**Course:** Machine Learning for Cyber Security (H-MLCS)  
**Institute:** K. J. Somaiya School of Engineering, Somaiya Vidyavihar University  
**Program:** B.Tech AI & Data Science | Sem VI | Batch A2  
**Roll No.:** 16014223080  

---

## Aim

To implement a Malicious URL Detection system using machine learning that classifies URLs as **malicious** or **benign** using data collection, preprocessing, feature extraction, model training, and prediction.

---

## Repository Structure

```
MLCS_Exp7_lab/
│
├── scraper.py                      # Step 1 — Scrapes malicious & benign URLs, outputs balanced dataset
├── mlcs_exp7_pipeline.py           # Steps 2–6 — Full ML pipeline (preprocessing → prediction)
│
├── urls_raw.xlsx                   # Raw scraped dataset (17,887 URLs before balancing)
├── urls_balanced.xlsx              # Balanced dataset (602 URLs — 301 malicious, 301 benign)
├── mlcs_exp7_full_pipeline.xlsx    # Final output with all results (9 sheets)
│
└── README.md
```

---

## Dataset

| Property | Value |
|---|---|
| Total URLs (raw) | 17,887 |
| Total URLs (balanced) | 602 |
| Malicious | 301 |
| Benign | 301 |
| Balancing Strategy | Undersampling |

**Malicious Sources:** OpenPhish, URLhaus, Cybercrime Tracker  
**Benign Sources:** Majestic Million, Cisco Umbrella Top-1M  

---

## Procedure

### Step 1 — Data Collection (`scraper.py`)
- Scrapes live threat intelligence feeds (OpenPhish, URLhaus, PhishTank, Cybercrime Tracker) for malicious URLs
- Scrapes trusted domain lists (Majestic Million, Cisco Umbrella) for benign URLs
- Removes duplicates and applies undersampling to balance classes
- Outputs `urls_raw.xlsx` and `urls_balanced.xlsx`

### Step 2 — Data Preprocessing
- Removed duplicates and null values
- Stripped whitespace from URL strings
- Filtered non-HTTP entries
- Verified balanced class distribution: 301 Malicious, 301 Benign

### Step 3 — Feature Extraction
23 features extracted per URL across 4 categories:

| Category | Features |
|---|---|
| Length-based | `url_length`, `hostname_length`, `path_length`, `query_length` |
| Count-based | `num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, `num_digits`, `num_query_params`, `num_subdomains`, `num_special_chars` |
| Binary Flags | `has_https`, `has_at_symbol`, `has_double_slash`, `has_ip_address`, `has_port`, `has_suspicious_tld`, `is_url_shortener`, `has_hex_encoding`, `has_suspicious_words` |
| Ratio-based | `digit_ratio`, `special_char_ratio` |

### Step 4 — Model Selection
Five classification models selected:
- Random Forest
- Gradient Boosting
- Decision Tree
- Logistic Regression
- SVM (Support Vector Machine)

### Step 5 — Model Training & Evaluation
- Train/Test split: 80% / 20% with stratification
- 5-Fold Stratified Cross-Validation
- Metrics: Accuracy, Precision, Recall, F1-Score, ROC-AUC

| Model | Accuracy | F1-Score | ROC-AUC |
|---|---|---|---|
| Random Forest | 100% | 100% | 100% |
| Gradient Boosting | 100% | 100% | 100% |
| Decision Tree | 100% | 100% | 100% |
| Logistic Regression | 100% | 100% | 100% |
| SVM | 100% | 100% | 100% |

**Best Model:** Random Forest (CV Std = 0.00%)

### Step 6 — Prediction on New URLs

| URL | Prediction | Confidence |
|---|---|---|
| https://www.google.com | Benign | 100% |
| https://www.wikipedia.org | Benign | 100% |
| http://verify-paypal-account.tk/login | Malicious | 98% |
| http://free-bitcoin-winner.xyz/claim | Malicious | 98% |
| http://192.168.1.1/admin/update.php | Malicious | 97% |
| http://swissborg-logine.webflow.io/ | Malicious | 100% |

---

## Output Excel — 9 Sheets

| Sheet | Contents |
|---|---|
| 1_Dataset_Summary | Overall dataset statistics |
| 2_Preprocessed_Data | Cleaned 602 URLs with labels |
| 3_Feature_Descriptions | All 23 features with descriptions |
| 4_Feature_Matrix | 602 × 23 feature values |
| 5_Model_Comparison | All metrics for all 5 models |
| 6_Classification_Reports | Per-class precision/recall/F1 |
| 7_Confusion_Matrices | TP/TN/FP/FN for each model |
| 8_New_URL_Predictions | 12 new URLs with predictions |
| 9_Feature_Importance | Features ranked by Random Forest |

---

## How to Run

```bash
# Install dependencies
pip install requests pandas openpyxl scikit-learn

# Step 1 — Scrape and build dataset
python scraper.py

# Steps 2–6 — Run full ML pipeline
python mlcs_exp7_pipeline.py
```

> **Note:** Keep `urls_balanced.xlsx` in the same folder as `mlcs_exp7_pipeline.py` before running.

---

## Conclusion

This experiment successfully implemented a malicious URL detection system using machine learning. Five classification models — Random Forest, Gradient Boosting, Decision Tree, Logistic Regression, and SVM — were trained on a balanced dataset of 602 URLs with 23 extracted features. All models achieved high accuracy, with Random Forest performing best, demonstrating that URL-based features like suspicious TLDs, keyword presence, and structural patterns are strong indicators of malicious intent. The trained model was validated on new unseen URLs, confirming its effectiveness as a real-time threat detection tool.

---

## Outcomes

**CO4:** Develop machine learning methodologies for both static and dynamic analysis of malware.

---

## References

- https://pmc.ncbi.nlm.nih.gov/articles/PMC10537824/
- https://www.nature.com/articles/s41598-025-34790-x.pdf
- VS Code, Claude, GeeksforGeeks
