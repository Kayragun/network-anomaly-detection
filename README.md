# Network Anomaly Detection Trained on Home Network Traffic

> *A personal project, built and maintained by a single developer. Feedback and issues are welcome.*

Watches your network traffic and flags anomalies in real time. It uses an IsolationForest model trained on your own home network traffic it learns what normal looks like, then alerts on anything that doesn't fit.

No attack labels, no dataset download. The model is trained on your traffic, so it knows your devices the robot vacuum, the phone, the laptop. Anything that breaks from that pattern gets flagged.

## What you need

- Python 3.10+
- [Wireshark](https://www.wireshark.org/download.html) (includes tshark)
- [Npcap](https://npcap.com/#download) with WinPcap-compatible mode Windows only
- Administrator privileges for packet capture

```bash
pip install -r requirements.txt
```

## Setup

Follow these three steps and you'll end up with a model built entirely from your own home network's traffic one that knows what your devices normally do and flags anomalies on its own, no attack signatures or third-party datasets involved. The model is yours alone; nobody else's network looks like yours, so nobody else's model would work here.

**1. Capture your home traffic**

This is where the training data comes from. The script listens on your Wi-Fi adapter and records flow statistics packet counts, timings, byte totals not the actual content of your traffic. Run it for 20-30 minutes and just use your network like you normally would: browse, watch a video, let your phone and other devices sit on the network.

```bash
python src/capture_home.py --duration 1800 --interface Wi-Fi --output data/home_traffic.csv
```

The more variety it sees, the better. A capture that only covers five idle minutes won't teach the model much.

**2. Train the model on Google Colab**

Upload `notebooks/train.ipynb` and your `home_traffic.csv`. The notebook runs EDA first (feature distributions, correlation heatmap, PCA plot), then trains the model. Run all cells it takes a few seconds. Download `model.pkl` when done and put it in `models/`.

**3. Run the app**

Run as Administrator:

```bash
streamlit run app.py
```

Open http://localhost:8501.

## Testing it

`test_portscan.py` is a small helper that fakes a port scan against a target on your network. It connects to a dozen common ports one after another, which is exactly the kind of pattern the model should flag. Run it while monitoring is on to check that detection works:

```bash
python test_portscan.py 192.168.1.1
```

You should see the flows show up as Critical (purple) in the dashboard within about 10 seconds.

## Severity levels

Each flow gets one of five levels:

- **Green Safe:** normal traffic
- **Yellow Low:** mildly unusual
- **Orange Medium:** moderately unusual
- **Red High:** strongly anomalous
- **Purple Critical:** port scan, DDoS, or intrusion patterns

## What it sees (and what it doesn't)

Runs on your computer and watches traffic that reaches your machine. That shapes what it can catch:

- ✅ Someone joins your network and runs a scan usually caught. Scans start with ARP broadcasts ("who's at this address?") that every device on the network receives, including yours.
- ✅ Anything aimed directly at your computer caught. Those packets land on your adapter.
- ❌ A direct, no-scan attack on another device missed. That traffic never passes through your machine.
- ❌ An attack on the router from outside missed. It happens before traffic reaches your network.

In practice most attacks (and most automated tools) scan the network first, so the reconnaissance phase tends to show up even when the real target is something else. To cover the whole network instead of just your machine, this would need to run on the router or gateway see the notes in the repo's discussion for that setup.

## A note on sharing

Don't share your `model.pkl`. It's trained on your network's patterns, so it carries a statistical fingerprint of your traffic and it's useless to anyone else anyway, since their "normal" looks nothing like yours. Both `model.pkl` and your captured `data/` are kept out of git on purpose. Share the code, not the model.

## Reducing false positives

If you see too many false alarms, capture more traffic especially at different times of day and retrain. The model improves as it sees more of your network's normal patterns.

```bash
python src/capture_home.py --duration 3600 --interface Wi-Fi --output data/home_traffic.csv
```

## Features used by the model

Each flow is described by 78 numeric features — no IP addresses, no timestamps. The model sees:

- **Ports & protocol** — source/destination port, protocol number
- **Packet counts** — total forward and backward packets per flow
- **Packet sizes** — min, max, mean, std in each direction and overall
- **Throughput** — bytes/s and packets/s for the flow and each direction
- **Timing (IAT)** — inter-arrival time statistics (mean, std, min, max) for the flow and each direction
- **TCP flags** — counts of SYN, ACK, FIN, RST, PSH, URG, CWR, ECE flags
- **Flow shape** — down/up ratio, window sizes, active/idle durations, bulk transfer stats

IP addresses are dropped before training and inference, so DHCP address changes have no effect on detection.

## How it works

IsolationForest learns the structure of normal traffic. It doesn't need attack examples. It builds a bunch of random decision trees and measures how quickly each flow gets isolated from the rest unusual flows get separated fast, so a short path means something looks off.

The `contamination` parameter (default 1%) tells the model what fraction of your capture to treat as noise. Raise it if you have too many false alarms, lower it for stricter detection.

## Author

**Kayra Gun** [GitHub](https://github.com/Kayragun) · [LinkedIn](https://www.linkedin.com/in/kayragun/)
