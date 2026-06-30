import queue
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent / "src"))
from monitor import LiveMonitor, PYSHARK_AVAILABLE

MODEL_PATH = Path(__file__).parent / "models" / "model.pkl"


st.set_page_config(page_title="Vigil — Network IDS", page_icon="🛡️", layout="wide")

st.title("🛡️ Vigil — Network Anomaly Detection")
st.caption("Anomaly detection trained on your own home network traffic")

@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None, None, None
    a = joblib.load(MODEL_PATH)
    return a["model"], a["scaler"], a["feature_cols"]

model, scaler, feature_cols = load_model()

if model is None:
    st.error(
        "**model.pkl not found.**  \n"
        "Capture home traffic with `src/capture_home.py`, then run "
        "`notebooks/train.ipynb` on Google Colab and place `model.pkl` in `models/`."
    )
    st.stop()

with st.sidebar:
    st.header("Model Info")
    st.write(f"**Type:** Anomaly Detection (IsolationForest)")
    st.write(f"**Features:** {len(feature_cols)}")
    st.write(f"**Training data:** Home network traffic")

tab1, tab2, tab3 = st.tabs(["Single Prediction", "Batch Prediction (CSV)", "Live Monitoring"])

with tab1:
    st.subheader("Manual Feature Input")
    st.info("There are many features — use the Batch Prediction tab to upload a CSV row instead.")

    sample_input = {col: 0.0 for col in feature_cols}
    cols_per_row = 4
    feature_list = list(feature_cols)

    for i in range(0, min(len(feature_list), 20), cols_per_row):
        row_cols = st.columns(cols_per_row)
        for j, col in enumerate(feature_list[i:i + cols_per_row]):
            sample_input[col] = row_cols[j].number_input(col, value=0.0, key=f"feat_{col}")

    if st.button("Predict", type="primary"):
        import numpy as np
        row_df = pd.DataFrame([sample_input])
        X = scaler.transform(row_df[feature_cols].values)
        pred = model.predict(X)[0]
        score = model.decision_function(X)[0]
        label = "Benign" if pred == 1 else "Anomaly"
        confidence = float(np.clip(abs(score) / 0.2, 0.0, 1.0))

        if pred == 1:
            st.success(f"**{label}** — Anomaly score: {score:.4f}")
        else:
            st.error(f"**{label}** — Anomaly score: {score:.4f}")

        st.caption("Score < 0 = anomaly. More negative = more unusual.")

with tab2:
    st.subheader("Batch Prediction via CSV Upload")
    uploaded = st.file_uploader("Upload a CSV file containing feature columns", type=["csv"])

    if uploaded:
        import numpy as np
        df = pd.read_csv(uploaded, low_memory=False)
        available = [c for c in feature_cols if c in df.columns]
        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            st.warning(f"Missing {len(missing)} columns — filling with 0.")
            for c in missing:
                df[c] = 0.0
        X = scaler.transform(df[feature_cols].values)
        preds = model.predict(X)
        scores = model.decision_function(X)
        df["prediction"] = ["Benign" if p == 1 else "Anomaly" for p in preds]
        df["anomaly_score"] = scores

        st.write(f"**{len(df)} records** processed.")
        st.dataframe(df[["prediction", "anomaly_score"]].head(100))

        attack_counts = df["prediction"].value_counts()
        st.bar_chart(attack_counts)

        csv_out = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download Results (CSV)", csv_out, "vigil_predictions.csv", "text/csv")

with tab3:
    st.subheader("Live Network Monitoring")

    if not PYSHARK_AVAILABLE:
        st.error("Wireshark (tshark) not found. Download from wireshark.org and ensure tshark is installed.")
        st.stop()

    if "monitor" not in st.session_state:
        st.session_state.monitor = None
        st.session_state.alert_log = []

    col_start, col_stop, col_info = st.columns([1, 1, 3])

    with col_start:
        start_disabled = st.session_state.monitor is not None and st.session_state.monitor.is_running()
        if st.button("Start Monitoring", type="primary", disabled=start_disabled):
            interface = st.session_state.get("iface", "Wi-Fi")
            alert_q = queue.Queue(maxsize=500)
            mon = LiveMonitor(interface=interface, alert_queue=alert_q)
            mon.start()
            st.session_state.monitor = mon
            st.session_state.alert_log = []

    with col_stop:
        stop_disabled = st.session_state.monitor is None or not st.session_state.monitor.is_running()
        if st.button("Stop", disabled=stop_disabled):
            st.session_state.monitor.stop()

    with col_info:
        iface = st.text_input("Network Interface", value="Wi-Fi", key="iface", label_visibility="collapsed")

    st.caption("Each flow is scored after 5s of inactivity")

    # Drain queue and update log
    if st.session_state.monitor:
        alert_q = st.session_state.monitor.alert_queue
        new_records = []
        while not alert_q.empty():
            try:
                rec = alert_q.get_nowait()
                new_records.append(rec)
            except queue.Empty:
                break

        if new_records:
            st.session_state.alert_log = (new_records + st.session_state.alert_log)[:2000]

    # Display results
    if st.session_state.alert_log:
        log = [r for r in st.session_state.alert_log if "error" not in r]
        errors = [r for r in st.session_state.alert_log if "error" in r]
        attacks = [r for r in log if r.get("is_attack")]
        benign = [r for r in log if not r.get("is_attack")]

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Flows", len(log))
        m2.metric("Anomalies", len(attacks))
        m3.metric("Normal", len(benign))

        for err in errors:
            st.error(err["error"])

        if attacks:
            st.error(f"**{len(attacks)} anomaly(ies) detected!**")
            attack_df = pd.DataFrame(attacks)[["timestamp", "src_ip", "dst_ip", "dst_port", "label", "confidence"]]
            attack_df["confidence"] = attack_df["confidence"].map("{:.1%}".format)
            st.dataframe(attack_df, use_container_width=True)

        with st.expander("All Flows"):
            if log:
                all_df = pd.DataFrame(log)[["timestamp", "src_ip", "dst_ip", "label", "confidence"]]
                all_df["confidence"] = all_df["confidence"].map("{:.1%}".format)
                st.dataframe(all_df.head(50), use_container_width=True)

    elif st.session_state.monitor and st.session_state.monitor.is_running():
        st.info("Waiting for flows... (each flow appears after 5 seconds of inactivity)")

    # Auto-refresh while running
    if st.session_state.monitor and st.session_state.monitor.is_running():
        time.sleep(2)
        st.rerun()
