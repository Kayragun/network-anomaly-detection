"""
Home traffic capture script for Vigil.

Captures live network traffic using cicflowmeter and saves it as a CSV.
This is the training data for the anomaly detection model — run it while
using your network normally so the model learns what your traffic looks like.

Usage (run as Administrator):
    python src/capture_home.py --duration 1800 --interface Wi-Fi --output data/home_traffic.csv

Upload the output CSV to Colab and run notebooks/train.ipynb to build the model.
"""
import argparse
import csv
import time
from pathlib import Path

from cicflowmeter.flow_session import FlowSession
from cicflowmeter.writer import OutputWriter
from scapy.all import AsyncSniffer

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

MODEL_COLS = list(CIC_TO_MODEL.values())
CSV_HEADER = MODEL_COLS + ["Label"]


class _BenignWriter(OutputWriter):
    def __init__(self, csv_writer, counter):
        self.csv_writer = csv_writer
        self.counter = counter

    def write(self, data: dict):
        try:
            row = {}
            for cic_col, model_col in CIC_TO_MODEL.items():
                val = data.get(cic_col, 0.0)
                row[model_col] = float(val) if val is not None else 0.0
            row["Label"] = "Benign"
            self.csv_writer.writerow([row.get(c, 0.0) for c in CSV_HEADER])
            self.counter[0] += 1
            if self.counter[0] % 50 == 0:
                print(f"  {self.counter[0]} akış kaydedildi...")
        except Exception:
            pass


def capture(interface: str, duration: int, output: str):
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    counter = [0]
    print(f"Yakalama başladı: {interface} — {duration} saniye")
    print(f"Çıktı: {output_path}")
    print("Bilgisayarınızı normal şekilde kullanın (tarayıcı, video, uygulama)...")
    print("Durdurmak için Ctrl+C\n")

    with open(output_path, "w", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(CSV_HEADER)

        import tempfile, os
        tmp = tempfile.mktemp(suffix=".csv")
        writer = _BenignWriter(csv_writer, counter)
        session = FlowSession(output_mode="csv", output=tmp)
        session.output_writer = writer
        if os.path.exists(tmp):
            os.unlink(tmp)

        sniffer = AsyncSniffer(
            iface=interface,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
        sniffer.start()

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\nDurduruldu.")

        sniffer.stop()
        session.flush_flows()

    print(f"\nTamamlandi! {counter[0]} akis kaydedildi -> {output_path}")
    print("Bu dosyayi Colab'da train.ipynb ile modeli egitmek icin kullanin.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ev agi trafigi yakala (Benign etiketli)")
    parser.add_argument("--interface", default="Wi-Fi")
    parser.add_argument("--duration", type=int, default=600)
    parser.add_argument("--output", default="data/home_traffic.csv")
    args = parser.parse_args()
    capture(args.interface, args.duration, args.output)
