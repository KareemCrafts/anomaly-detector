# 🛡️ Blue Team AI Anomaly Detector

An AI-powered log analysis dashboard that detects suspicious login activity in real time using Machine Learning.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red) ![ML](https://img.shields.io/badge/ML-Isolation%20Forest-green)

## What it does
- Ingests Windows Security Event logs or Linux auth.log files
- Detects anomalies using the Isolation Forest ML algorithm
- Visualizes threats on an interactive dark-themed dashboard
- Explains why each event was flagged (off-hours, high attempts, login failures)
- Exports flagged events as CSV for further investigation

## Screenshots
[Add your dashboard screenshot here]

## Tech Stack
| Tool | Purpose |
|------|---------|
| Python | Core language |
| Scikit-learn | Isolation Forest anomaly detection |
| Streamlit | Interactive web dashboard |
| Plotly | Interactive charts |
| Pandas | Log parsing and feature engineering |

## How to run it

1. Install dependencies:
pip install pandas scikit-learn streamlit plotly

2. Run the dashboard:
streamlit run detector.py

3. Upload your logs from the sidebar or use demo data

## What I learned
- How to parse and analyze real Windows Security Event logs
- Why false positives are one of the biggest challenges in blue team work
- How ML models like Isolation Forest detect outliers without labeled data
- The importance of tuning anomaly sensitivity to reduce alert fatigue

## Author
Kareem — Cybersecurity enthusiast focused on blue team operations

Dashboard<img width="2559" height="1464" alt="AIDetector" src="https://github.com/user-attachments/assets/9728e343-bf40-4afe-8264-8a66c210c788" />

