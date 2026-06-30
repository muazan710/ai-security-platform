# AI Security Intelligence Platform

An end-to-end ML-powered system that analyzes a URL and predicts whether it is
**Safe**, **Suspicious**, or **Malicious**, with human-readable, explainable
reasoning behind every prediction.

```
Input:  https://secure-paypal-login-example.com
Output:
  Risk Level: HIGH
  Prediction: malicious
  Confidence: 80.6%
  Reasons:
    - Contains suspicious keyword(s): login, secure, paypal
```

---

## 1. Architecture

```
                ┌─────────────────────┐
                │   Frontend (HTML)   │
                │  index.html + JS    │
                └─────────┬───────────┘
                          │ POST /predict
                          ▼
                ┌─────────────────────┐
                │   FastAPI Backend   │
                │  - rate limiting    │
                │  - input validation │
                │  - feature extract  │
                │  - model inference  │
                │  - explainability   │
                └─────────┬───────────┘
                          │ loads
                          ▼
        ┌──────────────────────────────────┐
        │            model/                │
        │ best_model.joblib (RandomForest) │
        │ label_encoder.joblib             │
        │ features.py (shared extractor)   │
        │ metrics.json                     │
        └──────────────────────────────────┘
                          ▲
                          │ trained on
        ┌──────────────────────────────────┐
        │           dataset/                │
        │   phishing_dataset.csv            │
        └──────────────────────────────────┘
```

See `architecture.png` for the rendered diagram (generated from this
description — open in any image viewer).

**Why this design:**
- `features.py` is a single shared module imported by both the training
  script and the API, so the features the model is *served* with always
  match the features it was *trained* on (a very common source of
  train/serve skew bugs in real ML systems).
- The model artifacts are loaded once at API startup (not per-request) for
  low latency.

---

## 2. Dataset (Part 1)

**Source & why:** This environment had no internet access to pull a live
Kaggle/UCI CSV, so `dataset/generate_dataset.py` builds a dataset that
**mirrors the exact structural patterns** documented in the UCI "Phishing
Websites Dataset" and Kaggle "Phishing Site URLs" research (IP-based URLs,
excessive subdomains, suspicious keywords, shortened URLs, suspicious TLDs,
lookalike brand domains) combined with ~45 real, well-known legitimate
domains for the safe class. `load_real_dataset()` in the same file is a
one-line swap-in point to plug in the actual Kaggle/UCI CSV once you have
internet access — no other code needs to change, since `features.py`
operates on raw URL strings.

- **Size:** 1,373 URLs after de-duplication (600 malicious / 567 safe / 206 suspicious)
- **Cleaning:** dropped nulls, dropped duplicate URLs
- **Limitations:**
  - Synthetic generation means it will not capture every real-world phishing
    technique (e.g. homograph/unicode attacks, compromised legitimate sites,
    very recent campaigns) — a real Kaggle/UCI/PhishTank dataset should
    replace it before production use.
  - Class "suspicious" is the hardest to define consistently even for
    humans — it is intentionally a noisier gray-zone class.
  - No live signals (domain age, WHOIS, redirect chains, SSL cert issuer)
    are available without network/API access — these are flagged as
    feature engineering "if possible" extensions below.
- **Feature importance:** see `model/feature_importance.png` — suspicious
  keyword count, TLD suspicion, and IP-based URL detection are the top
  signals for the trained model.

Run `python dataset/generate_dataset.py` to regenerate.

---

## 3. Feature Engineering (Part 2)

All features are extracted in `model/features.py` (shared by training + API):

| Category | Features |
|---|---|
| URL | length, dot count, hyphen count, special char count, HTTPS flag, `@` symbol, digit ratio, domain entropy, suspicious keyword count, path length |
| Domain | subdomain count, domain length, TLD suspicion flag |
| Security | IP-address-based URL detection, shortened-URL detection, redirect-count proxy, port presence |

**Note on domain age / live redirect count:** true domain-age (WHOIS) and
live redirect-chain following both require outbound network/API calls
(e.g. WHOIS API, following HTTP redirects) which are not available in this
sandboxed environment. The code is structured so these can be added as two
extra columns in `features.py` + `FEATURE_COLUMNS` without touching the rest
of the pipeline — see `# TODO: live signals` markers.

---

## 4. Machine Learning Model (Part 3)

Three models trained and compared in `model/train.py`:

| Model | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) |
|---|---|---|---|---|
| Logistic Regression | 96.7% | 96.8% | 93.2% | 94.7% |
| **Random Forest (selected)** | **97.5%** | 95.6% | **96.9%** | **96.2%** |
| XGBoost | 97.5% | 95.6% | 96.9% | 96.2% |

Confusion matrices: `model/confusion_matrix_<ModelName>.png`
Comparison chart: `model/model_comparison.png`

**Why Random Forest was selected:** XGBoost tied it on every metric, but
Random Forest was chosen as the production model because (a) it is far less
prone to overfitting on a relatively small/synthetic dataset, (b) it
requires no hyperparameter tuning to reach this performance, (c) its
`feature_importances_` are simpler to expose to non-technical users than
gradient boosting's, and (d) inference latency difference is negligible at
this scale. In a system with millions of real labelled URLs, XGBoost would
likely pull ahead and would be the next thing to A/B test.

---

## 5. Explainability (Part 4)

Two layers of explainability are implemented:

1. **Global:** `model/feature_importance.png` — which features matter most
   across the whole model (Random Forest's built-in `feature_importances_`).
2. **Per-prediction (the part users actually see):** `_build_risk_factors()`
   in `backend/main.py` converts the raw extracted features of *this specific
   URL* into plain-English reasons ("Contains suspicious keyword: login",
   "Excessive subdomain usage", "Uses a known URL shortening service", etc.)
   — this directly answers "why was this URL marked risky?" for any user,
   technical or not.

A **consistency safeguard** is also implemented: if the ML model assigns a
non-safe label with low confidence (<65%) but the rule-based explainability
layer finds **zero** actual red flags, the system overrides toward "safe"
rather than showing a confusing high-risk verdict with no supporting reason.
This was added specifically because a finite training set cannot cover every
legitimate new domain on the internet, and a verdict with no explanation is
worse than a slightly conservative one.

(SHAP is included in requirements.txt for further per-prediction
explanation; `feature_importance.png` plus the rule-based reasons cover the
explainability requirement end-to-end for this submission timeline.)

---

## 6. Backend API (Part 5)

FastAPI, `backend/main.py`.

### `GET /`
Health check + currently loaded model + its metrics.

### `POST /predict`
**Request**
```json
{ "url": "https://secure-paypal-login-example.com" }
```
**Response**
```json
{
  "url": "https://secure-paypal-login-example.com",
  "prediction": "malicious",
  "confidence": 0.8067,
  "risk_level": "HIGH",
  "risk_factors": ["Contains suspicious keyword(s): login, secure, paypal"],
  "feature_summary": { "...": "all extracted numeric features" }
}
```

Interactive docs auto-generated by FastAPI at `http://localhost:8000/docs`.

---

## 7. Dashboard (Part 6)

`frontend/index.html` — a single static HTML/JS file, no build step. Open it
directly in a browser (with the backend running) to:
- enter a URL
- see the prediction + risk level badge
- see a confidence bar
- see the plain-English risk factors
- expand "Show extracted features" for the raw feature values

Click the example chips to quickly test a phishing URL, a known-safe URL, a
brand-new unseen domain, an IP-based URL, and a shortened URL.

---

## 8. Security Considerations (Part 7)

| Threat | Description | Mitigation implemented / suggested |
|---|---|---|
| **Data poisoning** | Attacker submits crafted "safe-looking" malicious URLs into a future retraining pipeline (if user feedback is fed back into training) | Never auto-retrain on unverified user-submitted labels; require human review / trusted-source labelling before any sample enters the training set; monitor for sudden distribution shifts |
| **Adversarial URLs** | Attacker tweaks a malicious URL (e.g. adds harmless-looking subdomains, uses homograph/unicode lookalike characters, mixes in legitimate-looking padding) specifically to dodge the feature thresholds the model learned | Combine ML score with rule-based heuristics (already done here via `risk_factors`) so a single feature can't be gamed alone; add adversarial examples to training data; add Unicode/homograph normalization before feature extraction |
| **Model manipulation / model theft** | If model file or `/predict` responses leak too much internal detail, an attacker can reverse-engineer decision boundaries | Don't expose raw model weights publicly; rate-limit `/predict`; avoid returning raw probability vectors for *all* classes (only the top one) in production; log and monitor for systematic probing patterns (many near-boundary queries from one client) |
| **API abuse** | Bulk scraping the prediction API to test thousands of phishing URLs and find which ones bypass detection, or denial-of-service | Implemented: basic in-memory rate limiter (60 req/min in `backend/main.py`); production: API keys / OAuth, per-key quotas, Web Application Firewall, request size limits (`url` capped at 2048 chars), CORS restricted to known frontend origin (currently `*` for local dev demo only) |
| **Input injection** | Malformed/oversized URL strings sent to crash parsing logic | `extract_features()` wraps `urlparse` in try/except and falls back safely; Pydantic validates request shape and length before it reaches feature extraction |

---

## 9. Setup Instructions (Part 8)

### Local (no Docker)
```bash
# 1. Install deps
pip install -r backend/requirements.txt

# 2. (Optional) regenerate dataset + retrain model
python dataset/generate_dataset.py
python model/train.py

# 3. Run backend
cd backend
uvicorn main:app --reload --port 8000

# 4. Open the dashboard
# Just open frontend/index.html directly in your browser
```

### Docker
```bash
docker build -t ai-security-platform .
docker run -p 8000:8000 ai-security-platform
# then open frontend/index.html in a browser
```

---

## 10. Interview Discussion — Quick Answers

1. **Why this ML model?** Random Forest: best macro-F1 tied with XGBoost,
   simpler to maintain/tune, less overfitting risk on a smaller dataset, and
   transparent feature importances. Re-evaluate against XGBoost once a much
   larger labelled dataset is available.
2. **How can attackers bypass detection?** Homograph domains, compromised
   legitimate infrastructure, very short-lived "fast-flux" domains, padding
   URLs to dilute keyword-density features, using HTTPS + clean TLDs to
   defeat the more obvious heuristics. Mitigation: ensemble of ML + rule
   heuristics + external threat intel (VirusTotal) rather than relying on
   any single signal.
3. **How to scale to millions of URLs?** Move from a single in-process model
   to a stateless API behind a load balancer; cache predictions for
   recently-seen URLs/domains (Redis); batch feature extraction; move model
   inference to a dedicated serving layer (e.g. ONNX/Triton) if latency
   becomes a bottleneck; precompute domain-level reputation scores async.
4. **How to monitor model drift?** Track prediction distribution and
   confidence histograms over time, log a sample of predictions vs. later
   ground truth (e.g. confirmed phishing takedowns), alert on feature
   distribution shifts (e.g. PSI/KL-divergence on `url_length`,
   `entropy`, etc.), scheduled retraining cadence with held-out validation
   sets.
5. **How to secure the prediction API?** API key auth + per-key rate
   limiting (basic version implemented), HTTPS only, input length/shape
   validation (implemented via Pydantic), restrict CORS origins in
   production, don't leak full probability vectors or model internals, log
   and alert on abuse patterns, run behind a WAF.

---

## 11. Project Structure

```
project/
├── backend/
│   ├── main.py            # FastAPI app
│   └── requirements.txt
├── frontend/
│   └── index.html         # single-file dashboard
├── model/
│   ├── features.py         # shared feature extraction
│   ├── train.py             # trains & compares 3 models
│   ├── best_model.joblib
│   ├── label_encoder.joblib
│   ├── metrics.json
│   ├── confusion_matrix_*.png
│   ├── feature_importance.png
│   └── model_comparison.png
├── dataset/
│   ├── generate_dataset.py
│   └── phishing_dataset.csv
├── notebooks/              # (optional EDA notebook can go here)
├── Dockerfile
└── README.md
```

---

## 12. Bonus / Future Work (not implemented in this timeline)

- **AI Security Agent:** wire the existing `risk_factors` list into an LLM
  prompt to generate a conversational explanation ("Why is this dangerous?")
  — the rule-based reasons already produced are a ready-made grounding
  source for this, avoiding hallucination.
- **Real-time threat intel:** call VirusTotal's API with the URL/domain and
  display it side-by-side with the ML verdict; flag disagreements for human
  review. Not implemented here due to no outbound internet access in this
  environment + 1-day timeline — code is structured (`risk_factors` is a
  list, easy to append a `"VirusTotal: X/90 engines flagged"` entry to).
