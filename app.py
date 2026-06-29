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

# Flows below this confidence threshold are not flagged as attacks
ATTACK_THRESHOLD = 0.95

# Common service ports that are not attack targets in home networks
SAFE_PORTS = {80, 443, 53, 67, 68, 123, 5353, 1900, 5355}

def is_whitelisted(rec):
    """Return True if this flow is almost certainly benign home traffic."""
    src = rec.get("src_ip", "")
    dst = rec.get("dst_ip", "")
    dst_port = rec.get("dst_port", 0)
    if src.startswith("192.168.") and dst.startswith("192.168."):
        return True
    if dst_port in SAFE_PORTS:
        return True
    # Ephemeral ports are response traffic to outbound connections we initiated
    if dst_port >= 32768:
        return True
    return False

st.set_page_config(page_title="Vigil — Network IDS", page_icon="🛡️", layout="wide")

st.title("🛡️ Vigil — Network Anomaly Detection")
st.caption("Random Forest IDS trained on the TII-SSRC-23 dataset")

@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None, None, None, None
    a = joblib.load(MODEL_PATH)
    return a["model"], a["scaler"], a["label_encoder"], a["feature_cols"]

model, scaler, label_encoder, feature_cols = load_model()

if model is None:
    st.error(
        "**model.pkl not found.**  \n"
        "Run `notebooks/train.ipynb` on Google Colab and place the downloaded "
        "`model.pkl` in the `models/` folder."
    )
    st.stop()

with st.sidebar:
    st.header("Model Info")
    st.write(f"**Classes:** {', '.join(label_encoder.classes_)}")
    st.write(f"**Features:** {len(feature_cols)}")
    st.write(f"**Model:** RandomForestClassifier")

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
        row_df = pd.DataFrame([sample_input])
        X = scaler.transform(row_df[feature_cols].values)
        pred_idx = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        label = label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(proba.max())

        if label.lower() == "benign":
            st.success(f"**Sonuç: {label}** — Güven: {confidence:.1%}")
        else:
            st.error(f"**Sonuç: {label}** — Güven: {confidence:.1%}")

        proba_df = pd.DataFrame({"Class": label_encoder.classes_, "Probability": proba}).sort_values("Probability", ascending=False)
        st.bar_chart(proba_df.set_index("Class"))

with tab2:
    st.subheader("Batch Prediction via CSV Upload")
    uploaded = st.file_uploader("Upload a CSV file containing feature columns", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded, low_memory=False)
        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            st.error(f"Missing columns: {missing}")
        else:
            X = scaler.transform(df[feature_cols].values)
            preds = model.predict(X)
            probas = model.predict_proba(X).max(axis=1)
            df["prediction"] = label_encoder.inverse_transform(preds)
            df["confidence"] = probas

            st.write(f"**{len(df)} records** processed.")
            st.dataframe(df[["prediction", "confidence"]].head(100))

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

    st.caption(f"Attack threshold: confidence > {ATTACK_THRESHOLD:.0%}  |  Flows are classified after 5s of inactivity")

    # Drain queue and update log
    if st.session_state.monitor:
        alert_q = st.session_state.monitor.alert_queue
        new_records = []
        while not alert_q.empty():
            try:
                rec = alert_q.get_nowait()
                if rec.get("is_attack"):
                    if is_whitelisted(rec) or rec.get("confidence", 0) < ATTACK_THRESHOLD:
                        rec["is_attack"] = False
                        rec["label"] = "Benign"
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
        m2.metric("Attacks", len(attacks))
        m3.metric("Benign", len(benign))

        for err in errors:
            st.error(err["error"])

        if attacks:
            st.error(f"**{len(attacks)} attack(s) detected!**")
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
