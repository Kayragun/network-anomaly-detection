import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

DROP_COLS = ["Flow ID", "Src IP", "Dst IP", "Timestamp",
             "Traffic Type", "Traffic Subtype", "Label", "label",
             "src_ip", "dst_ip", "timestamp", "flow_id"]


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df = df[numeric_cols]
    return df


def preprocess(path: str) -> tuple:
    """
    Load and clean home traffic CSV for anomaly detection training.

    Returns: (X_scaled, scaler, feature_names)
    """
    df = pd.read_csv(path, low_memory=False, on_bad_lines="skip")
    df = clean(df)

    feature_cols = list(df.columns)
    scaler = StandardScaler()
    X = scaler.fit_transform(df[feature_cols].values)

    return X, scaler, feature_cols
