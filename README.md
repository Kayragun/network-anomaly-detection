# Vigil — Network Anomaly Detection

Vigil watches your network traffic and flags attacks in real time. It uses a Random Forest model trained on the TII-SSRC-23 dataset to classify each flow as Benign or Malicious.

Detects DoS/DDoS, port scanning, and brute-force attacks. Won't catch WPA password cracking — that happens at Layer 2, below what Vigil can see.

Vigil is a personal project, built and maintained by a single developer. Feedback and issues are welcome.

## What you need

- Python 3.10+
- [Wireshark](https://www.wireshark.org/download.html) (includes tshark)
- [Npcap](https://npcap.com/#download) with WinPcap-compatible mode — Windows only
- Administrator privileges for packet capture

```bash
pip install -r requirements.txt
```

## Setup

**1. Get the dataset**

Download [TII-SSRC-23 from Kaggle](https://www.kaggle.com/datasets/daniaherzalla/tii-ssrc-23) (CSV) and put it in `data/`.

**2. Train the model on Google Colab**

Upload `notebooks/train.ipynb`, run all cells. The notebook asks for your Kaggle API token (`kaggle.json`) to download the data automatically. Download `model.pkl` when it's done and put it in `models/`.

> Free Colab works fine — the notebook loads 4M rows by default to stay within the RAM limit.

**3. Run the app**

Run as Administrator:

```bash
streamlit run app.py
```

Open http://localhost:8501.

## Reducing false positives (optional)

If you see too many false alarms, capture 10 minutes of your own normal traffic and use it to fine-tune the model:

```bash
python src/capture_home.py --duration 600 --interface Wi-Fi --output data/home_traffic.csv
```

Upload the CSV in the fine-tuning cell of `train.ipynb` and retrain.

## Results

Trained on 4M rows. Accuracy alone is misleading here — the dataset is 99.84% Malicious, so a model that predicts everything as Malicious would score 99.84% without ever identifying a single normal connection. The metrics that matter:

| | Benign | Malicious |
|---|---|---|
| Precision | 100% | 99.999% |
| Recall | 99.7% | 100% |
| F1 | 99.8% | 100% |

- **False positive rate: 0%** — no legitimate traffic was flagged as an attack
- **False negative rate: 0.3%** — 4 out of 1282 Benign flows were missed

The high Benign recall is the result of training with `class_weight='balanced'`, which prevents the model from ignoring the minority class.

## Dataset Citation

```bibtex
@article{herzalla2023tii,
  title={TII-SSRC-23 Dataset: Typological Exploration of Diverse Traffic Patterns for Intrusion Detection},
  author={Herzalla, Dania and Lunardi, Willian T and Andreoni, Martin},
  journal={IEEE Access},
  year={2023},
  doi={10.1109/ACCESS.2023.3319213}
}
```

**Dataset License:** CC BY-NC-ND 4.0 — Research/portfolio use only.

## Author

**Kayra Gun** — [GitHub](https://github.com/Kayragun) · [LinkedIn](https://www.linkedin.com/in/kayragun/)
