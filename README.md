# Vigil — Network Anomaly Detection

Vigil watches your network traffic and flags anomalies in real time. It uses an IsolationForest model trained on your own home network traffic — it learns what normal looks like, then alerts on anything that doesn't fit.

No attack labels, no dataset download. The model is trained on your traffic, so it knows your devices — the robot vacuum, the phone, the laptop. Anything that breaks from that pattern gets flagged.

> *Vigil is a personal project, built and maintained by a single developer. Feedback and issues are welcome.*

## What you need

- Python 3.10+
- [Wireshark](https://www.wireshark.org/download.html) (includes tshark)
- [Npcap](https://npcap.com/#download) with WinPcap-compatible mode — Windows only
- Administrator privileges for packet capture

```bash
pip install -r requirements.txt
```

## Setup

**1. Capture your home traffic**

This is where the training data comes from. The script listens on your Wi-Fi adapter and records flow statistics — packet counts, timings, byte totals — not the actual content of your traffic. Run it for 20-30 minutes and just use your network like you normally would: browse, watch a video, let your phone and other devices sit on the network.

```bash
python src/capture_home.py --duration 1800 --interface Wi-Fi --output data/home_traffic.csv
```

The more variety it sees, the better. A capture that only covers five idle minutes won't teach the model much.

**2. Train the model on Google Colab**

Upload `notebooks/train.ipynb` and your `home_traffic.csv`. Run all cells — it takes a few seconds. Download `model.pkl` when done and put it in `models/`.

**3. Run the app**

Run as Administrator:

```bash
streamlit run app.py
```

Open http://localhost:8501.

## Reducing false positives

If you see too many false alarms, capture more traffic — especially at different times of day — and retrain. The model improves as it sees more of your network's normal patterns.

```bash
python src/capture_home.py --duration 3600 --interface Wi-Fi --output data/home_traffic.csv
```

## How it works

IsolationForest learns the structure of normal traffic. It doesn't need attack examples. It builds a bunch of random decision trees and measures how quickly each flow gets isolated from the rest — unusual flows get separated fast, so a short path means something looks off.

The `contamination` parameter (default 1%) tells the model what fraction of your capture to treat as noise. Raise it if you have too many false alarms, lower it for stricter detection.

## Author

**Kayra Gun** — [GitHub](https://github.com/Kayragun) · [LinkedIn](https://www.linkedin.com/in/kayragun/)
