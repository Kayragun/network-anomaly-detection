# Vigil — Network Anomaly Detection System

A real-time network intrusion detection system (IDS) that monitors live traffic and classifies flows as **Benign** or **Malicious** using a Random Forest model trained on the TII-SSRC-23 dataset.

## Features

- **Live network monitoring** via Wireshark/tshark — captures and classifies every flow in real time
- **CICFlowMeter-compatible feature extraction** — the same 79 features used to generate the training dataset
- **Streamlit dashboard** — three tabs: manual prediction, batch CSV prediction, and live monitoring with attack alerts
- **Home traffic fine-tuning** — capture your own benign traffic to reduce false positives (`src/capture_home.py`)
- Detects: DoS/DDoS, port scanning, SSH/HTTP/FTP brute-force, and more

## Architecture

```
Live traffic
    └── tshark (Wireshark backend)
         └── cicflowmeter (flow feature extraction)
              └── RandomForestClassifier
                   └── Streamlit dashboard (alerts)
```

## Requirements

- Python 3.10+
- [Wireshark](https://www.wireshark.org/download.html) (with tshark) — for live monitoring
- [Npcap](https://npcap.com/#download) with **WinPcap API-compatible mode** — Windows only
- **Administrator privileges** — required for packet capture

```bash
pip install -r requirements.txt
```

## Setup

### 1. Dataset

Download from [Kaggle — TII-SSRC-23](https://www.kaggle.com/datasets/daniaherzalla/tii-ssrc-23) (CSV only) and place files in `data/`.

### 2. Kaggle API Token

Both notebooks download the dataset via the Kaggle API.

1. Kaggle.com → top-right avatar → **Settings** → API section
2. Click **Expire API Token** if one exists
3. Click **Create New API Token** → download `kaggle.json`
4. Upload `kaggle.json` when prompted in the notebook

### 3. EDA (Google Colab)

Upload `notebooks/eda.ipynb` to Colab and run all cells. Plots are saved to `notebooks/eda_plots/`.

> **Note:** The EDA notebook loads the first 500K rows to avoid crashing free Colab sessions (~12 GB RAM limit).

### 4. Train (Google Colab)

Upload `notebooks/train.ipynb` to Colab and run all cells. Download `model.pkl` and place it in `models/`.

> **Note:** The training notebook uses chunked loading with float32 dtype optimization and loads 4M rows by default. Loading the full 10M rows exceeds the free Colab RAM limit.

### 5. (Optional) Home Traffic Fine-Tuning

Capture your own benign home traffic to reduce false positives. Run as Administrator:

```bash
python src/capture_home.py --duration 600 --interface Wi-Fi --output data/home_traffic.csv
```

Use your computer normally during capture (browser, video, etc.). Upload the resulting CSV in the Colab notebook's fine-tuning cell.

### 6. Run the Streamlit App

Run as Administrator (required for live packet capture):

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501).

## Project Structure

```
Vigil/
├── app.py                  # Streamlit dashboard
├── src/
│   ├── monitor.py          # Live traffic monitor (cicflowmeter + tshark)
│   ├── capture_home.py     # Home traffic capture for fine-tuning
│   └── preprocess.py       # Data cleaning and encoding utilities
├── notebooks/
│   ├── eda.ipynb           # Exploratory data analysis (Colab)
│   └── train.ipynb         # Model training (Colab)
├── models/                 # Place model.pkl here after training
├── data/                   # Place dataset CSV files here (gitignored)
└── requirements.txt
```

## Model Notes

- **Class imbalance:** In the TII-SSRC-23 dataset, Benign traffic represents only ~0.04% of samples. The dataset is overwhelmingly Malicious.
- **Solution:** `RandomForestClassifier(class_weight='balanced')` assigns higher weight to the underrepresented Benign class automatically.
- **Feature extraction:** Uses [cicflowmeter](https://github.com/hieulw/cicflowmeter) to extract the same 79 CICFlowMeter features that the training dataset was generated with. This ensures live monitoring features match what the model was trained on.
- **False positive filtering:** Flows with confidence below 95% are not flagged as attacks. Local network traffic (192.168.x.x) and ephemeral ports (32768+) are whitelisted.

## Results

| Metric        | Value   |
|---------------|---------|
| Accuracy      | ~99.9%  |
| Benign recall | 99.7%   |
| Malicious recall | 100% |

Confusion matrix (4M row training run):
- Benign: 1278 / 1282 correct
- Malicious: 799,956 / 799,956 correct

## What Vigil Can and Cannot Detect

| Attack Type              | Detectable |
|--------------------------|------------|
| DoS / DDoS               | ✅ Yes     |
| Port scanning            | ✅ Yes     |
| SSH / HTTP brute-force   | ✅ Yes     |
| FTP / Telnet brute-force | ✅ Yes     |
| WPA password cracking    | ❌ No (Layer 2) |
| Deauth attacks           | ❌ No (Layer 2) |

WPA password cracking (e.g., aircrack-ng) operates at Layer 2 and generates no IP-layer traffic, making it invisible to flow-based IDS systems like Vigil.

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
