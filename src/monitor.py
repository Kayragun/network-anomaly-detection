"""
Live network monitor using cicflowmeter (CICFlowMeter-compatible feature extraction).
Features match the training data exactly, eliminating false positives from manual extraction.

Requirements:
  - pip install cicflowmeter scapy
  - Npcap installed (npcap.com) with WinPcap-compatible mode
  - Run as Administrator for packet capture
"""
import queue
import threading
import time
from pathlib import Path

import joblib
import pandas as pd

try:
    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.writer import OutputWriter
    from scapy.all import AsyncSniffer
    CICFLOW_AVAILABLE = True
except ImportError:
    CICFLOW_AVAILABLE = False

PYSHARK_AVAILABLE = CICFLOW_AVAILABLE  # alias for app.py

MODEL_PATH = Path(__file__).parent.parent / "models" / "model.pkl"

# cicflowmeter column → model feature name
CIC_TO_MODEL = {
    "src_port": "Src Port", "dst_port": "Dst Port", "protocol": "Protocol",
    "flow_duration": "Flow Duration", "tot_fwd_pkts": "Total Fwd Packet",
    "tot_bwd_pkts": "Total Bwd packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packet",
    "totlen_bwd_pkts": "Total Length of Bwd Packet",
    "fwd_pkt_len_max": "Fwd Packet Length Max", "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean", "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max", "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean", "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s", "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean", "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max", "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total", "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std", "fwd_iat_max": "Fwd IAT Max", "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total", "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std", "bwd_iat_max": "Bwd IAT Max", "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags", "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags", "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length", "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s", "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Packet Length Min", "pkt_len_max": "Packet Length Max",
    "pkt_len_mean": "Packet Length Mean", "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count", "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count", "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count", "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWR Flag Count", "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Fwd Segment Size Avg", "bwd_seg_size_avg": "Bwd Segment Size Avg",
    "fwd_byts_b_avg": "Fwd Bytes/Bulk Avg", "fwd_pkts_b_avg": "Fwd Packet/Bulk Avg",
    "fwd_blk_rate_avg": "Fwd Bulk Rate Avg", "bwd_byts_b_avg": "Bwd Bytes/Bulk Avg",
    "bwd_pkts_b_avg": "Bwd Packet/Bulk Avg", "bwd_blk_rate_avg": "Bwd Bulk Rate Avg",
    "subflow_fwd_pkts": "Subflow Fwd Packets", "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets", "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "FWD Init Win Bytes", "init_bwd_win_byts": "Bwd Init Win Bytes",
    "fwd_act_data_pkts": "Fwd Act Data Pkts", "fwd_seg_size_min": "Fwd Seg Size Min",
    "active_mean": "Active Mean", "active_std": "Active Std",
    "active_max": "Active Max", "active_min": "Active Min",
    "idle_mean": "Idle Mean", "idle_std": "Idle Std",
    "idle_max": "Idle Max", "idle_min": "Idle Min",
}


def cic_to_model_row(cic_data: dict, feature_cols) -> pd.DataFrame:
    row = {}
    for cic_col, model_col in CIC_TO_MODEL.items():
        if model_col in feature_cols:
            val = cic_data.get(cic_col, 0.0)
            row[model_col] = float(val) if val is not None else 0.0
    for col in feature_cols:
        if col not in row:
            row[col] = 0.0
    return pd.DataFrame([row])[list(feature_cols)]


class _ClassifyingWriter(OutputWriter):
    """Intercepts completed flows from FlowSession and classifies them."""

    def __init__(self, artifacts, alert_queue):
        self.artifacts = artifacts
        self.alert_queue = alert_queue

    def write(self, data: dict):
        try:
            src_ip = data.get("src_ip", "")
            dst_ip = data.get("dst_ip", "")
            src_port = int(data.get("src_port", 0))
            dst_port = int(data.get("dst_port", 0))
            protocol = int(data.get("protocol", 0))

            model = self.artifacts["model"]
            scaler = self.artifacts["scaler"]
            le = self.artifacts["label_encoder"]
            feature_cols = self.artifacts["feature_cols"]

            X_raw = cic_to_model_row(data, feature_cols)
            X = scaler.transform(X_raw.values)
            pred_idx = model.predict(X)[0]
            proba = model.predict_proba(X)[0]
            label = le.inverse_transform([pred_idx])[0]
            confidence = float(proba.max())

            record = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "label": label,
                "confidence": confidence,
                "is_attack": label.lower() != "benign",
            }
            if not self.alert_queue.full():
                self.alert_queue.put(record)
        except Exception:
            pass


class LiveMonitor:
    def __init__(self, interface=None, alert_queue=None):
        self.interface = interface or "Wi-Fi"
        self.alert_queue = alert_queue or queue.Queue(maxsize=500)
        self._stop_event = threading.Event()
        self._thread = None
        self._sniffer = None
        self.artifacts = None
        self._load_model()

    def _load_model(self):
        if MODEL_PATH.exists():
            self.artifacts = joblib.load(MODEL_PATH)

    def start(self, interface=None):
        if interface:
            self.interface = interface
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        if not CICFLOW_AVAILABLE:
            self.alert_queue.put({"error": "cicflowmeter veya scapy kurulu degil."})
            return
        if self.artifacts is None:
            self.alert_queue.put({"error": "model.pkl bulunamadi. models/ klasorune koyun."})
            return

        try:
            import tempfile, os
            tmp = tempfile.mktemp(suffix=".csv")
            writer = _ClassifyingWriter(self.artifacts, self.alert_queue)
            session = FlowSession(output_mode="csv", output=tmp)
            session.output_writer = writer
            if os.path.exists(tmp):
                os.unlink(tmp)

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter="ip and (tcp or udp)",
                prn=session.process,
                store=False,
            )
            self._sniffer.start()

            while not self._stop_event.is_set():
                time.sleep(0.5)

            self._sniffer.stop()
            session.flush_flows()

        except Exception as e:
            self.alert_queue.put({"error": str(e)})
