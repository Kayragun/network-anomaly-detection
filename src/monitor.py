"""
Live network monitor using cicflowmeter (CICFlowMeter-compatible feature extraction).
Features match the training data exactly, eliminating false positives from manual extraction.

Requirements:
  - pip install cicflowmeter scapy
  - Npcap installed (npcap.com) with WinPcap-compatible mode
  - Run as Administrator for packet capture
"""
import collections
import queue
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

try:
    import cicflowmeter.flow_session as _fs
    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.writer import OutputWriter
    from scapy.all import AsyncSniffer
    CICFLOW_AVAILABLE = True
    # Flush idle flows after 8s instead of the 240s default, and GC more often.
    # Patched here so it works on a fresh install without editing the package.
    _fs.EXPIRED_UPDATE = 8
    _fs.PACKETS_PER_GC = 50
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


PORT_SCAN_WINDOW = 30      # seconds to look back
PORT_SCAN_THRESHOLD = 4    # distinct dst ports to same dst_ip from same src_ip
PORT_SCAN_IGNORE = {80, 443, 8080, 8443}  # common web ports, skip in scan count


class _PortScanTracker:
    """Tracks distinct destination ports per (src_ip, dst_ip) pair in a sliding window."""

    def __init__(self, window=PORT_SCAN_WINDOW, threshold=PORT_SCAN_THRESHOLD):
        self.window = window
        self.threshold = threshold
        # (src_ip, dst_ip) -> deque of (timestamp, dst_port)
        self._hits: dict[tuple, collections.deque] = collections.defaultdict(
            lambda: collections.deque()
        )
        self._lock = threading.Lock()

    def record(self, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        """Record a connection; return True if port scan threshold exceeded."""
        if dst_port in PORT_SCAN_IGNORE:
            return False
        now = time.time()
        with self._lock:
            key = (src_ip, dst_ip)
            dq = self._hits[key]
            dq.append((now, dst_port))
            cutoff = now - self.window
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            distinct_ports = len({p for _, p in dq})
            return distinct_ports >= self.threshold


_port_scan_tracker = _PortScanTracker()


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
            feature_cols = self.artifacts["feature_cols"]

            X_raw = cic_to_model_row(data, feature_cols)
            X = scaler.transform(X_raw.values)
            pred = model.predict(X)[0]          # 1 = normal, -1 = anomaly
            score = model.decision_function(X)[0]  # higher = more normal

            label = "Benign" if pred == 1 else "Anomaly"
            # Convert score to a 0-1 confidence: clip score to [-0.2, 0.2] range
            confidence = float(np.clip(abs(score) / 0.2, 0.0, 1.0))

            # Skip broadcast/multicast destinations — IoT devices flood these normally
            is_broadcast = (
                dst_ip.endswith(".255") or
                dst_ip.startswith("224.") or
                dst_ip.startswith("239.")
            )

            # Heuristic port scan detection: many distinct dst ports to same host.
            # Identify the scanner as the side with the higher (ephemeral) port.
            is_port_scan = False
            if not is_broadcast:
                if src_port > dst_port:
                    scanner_ip, target_ip, service_port = src_ip, dst_ip, dst_port
                else:
                    scanner_ip, target_ip, service_port = dst_ip, src_ip, src_port
                is_port_scan = _port_scan_tracker.record(scanner_ip, target_ip, service_port)

            # Severity levels:
            #   Safe (green)     — normal traffic
            #   Low (yellow)     — mild anomaly
            #   Medium (orange)  — moderate anomaly
            #   High (red)       — strong anomaly
            #   Critical (purple)— port scan / extreme anomaly (scan, DDoS, intrusion)
            if is_broadcast:
                label, confidence, severity = "Benign", 1.0, "Safe"
            elif is_port_scan:
                label, confidence, severity = "Anomaly", 1.0, "Critical"
            elif pred == 1:
                label, severity = "Benign", "Safe"
            else:
                label = "Anomaly"
                if confidence < 0.4:
                    severity = "Low"
                elif confidence < 0.7:
                    severity = "Medium"
                elif confidence < 0.9:
                    severity = "High"
                else:
                    severity = "Critical"

            record = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "label": label,
                "severity": severity,
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

            # Periodically force garbage collection so idle flows get flushed
            # on a timer, not just when new packets happen to arrive.
            last_gc = time.time()
            while not self._stop_event.is_set():
                time.sleep(0.5)
                now = time.time()
                if now - last_gc >= 2:
                    try:
                        session.garbage_collect(now)
                    except Exception:
                        pass
                    last_gc = now

            self._sniffer.stop()
            session.flush_flows()

        except Exception as e:
            self.alert_queue.put({"error": str(e)})
