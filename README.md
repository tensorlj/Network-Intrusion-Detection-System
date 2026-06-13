# Network-Intrusion-Detection-System
Problem Statement
Every organisation running networked infrastructure faces a constant stream of malicious traffic — port scans
probing for open services, DDoS floods, brute-force credential attacks, SQL injection attempts, and lateral
movement by attackers already inside the network. Signature-based firewalls catch known patterns but miss novel
variants. An ML-based NIDS that classifies traffic flows by attack type in real time provides a second layer of
defence that generalises beyond known signatures.

Stack & Dataset
Primary dataset CIC-IDS-2017 (Canadian Institute for Cybersecurity) — 2.8M flows, 14 attack types, free
Supplementary UNSW-NB15 — 2.5M records, 9 attack categories (free). NSL-KDD for benchmark
comparison
Model Gradient Boosted Trees (XGBoost / LightGBM) for tabular flow features — fast,
interpretable
Explainability SHAP values per prediction — shows which flow features drove the classification
Deployment FastAPI microservice + Streamlit dashboard — real-time flow classification and alerting

Expected Features
• Multi-class attack classification: Classifies each network flow into one of 14 categories: Benign, DDoS,
PortScan, Brute Force (SSH/FTP/Web), Heartbleed, Botnet, Infiltration, Web Attacks (SQL Injection, XSS,
Brute Force), and DoS variants (Slowloris, Hulk, GoldenEye). This is more useful than binary
benign/malicious — knowing it is a port scan vs active infiltration triggers different response protocols.
• Flow feature extraction: Raw packets are aggregated into flow records (source/dest IP, port, protocol,
duration, byte counts, packet lengths, inter-arrival times, TCP flags). These 80 features per flow are the
model input — no deep packet inspection needed, meaning the system works on encrypted traffic too.
• Gradient boosted classifier: XGBoost/LightGBM trains on flow features to classify attack types. Training
completes in under 15 minutes on CPU. Inference is microseconds per flow — fast enough for real-time
classification at line rate on a 1Gbps link without GPU.
• SHAP explainability: Every classification comes with SHAP feature attributions — a DDoS alert shows that
high packet rate and low byte-per-packet ratio drove the decision. This turns a black-box alert into an
actionable explanation for the SOC analyst, dramatically reducing false positive fatigue.
• Anomaly detection fallback: An Isolation Forest runs in parallel on flows that the classifier marks as
uncertain. Novel attack patterns that don't match any training category are surfaced as anomalies rather
than silently misclassified as benign.
• Real-time scoring API: A FastAPI endpoint accepts a flow feature vector and returns classification,
confidence, top contributing features, and recommended response action in under 1ms. Designed to
integrate with existing SIEM tools (Splunk, Elastic) via a webhook.
• Alert dashboard: Streamlit dashboard showing live traffic classification breakdown, attack type distribution
over time, top source IPs flagged, geographic origin map of suspicious flows, and a per-alert detail view with
SHAP explanation.
• Threshold tuning interface: Operators can adjust the confidence threshold per attack class — a SOC
running lean might accept more false positives on DDoS (easy to verify) while demanding high precision on
Infiltration alerts (expensive to investigate). The dashboard shows precision/recall tradeoffs live as
thresholds are adjusted.
• Benchmark report: Evaluated against NSL-KDD and UNSW-NB15 benchmarks in addition to CIC-IDS-
2017 — giving comparable results to published academic baselines so the model's performance can be
contextualised.

Success Metrics
Classification
accuracy
> 98% on CIC-IDS-2017 held-out test set
False positive rate < 1% on benign traffic — critical for operational usability
Inference speed < 1 ms per flow on CPU — real-time at 1 Gbps line rate
Explainability SHAP explanations for 100% of alerts — zero black-box outputs
