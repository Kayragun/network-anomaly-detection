import joblib
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "models" / "model.pkl"


def load_artifacts(model_path: str | Path = MODEL_PATH) -> tuple:
    """Loads model, scaler, and feature columns from model.pkl."""
    artifacts = joblib.load(model_path)
    return artifacts["model"], artifacts["scaler"], artifacts["feature_cols"]


def predict_single(row: dict, model_path: str | Path = MODEL_PATH) -> dict:
    """Scores a single flow. Returns label, anomaly score, and confidence."""
    model, scaler, feature_cols = load_artifacts(model_path)
    df = pd.DataFrame([row])[feature_cols]
    X = scaler.transform(df.values)
    pred = model.predict(X)[0]            # 1 = normal, -1 = anomaly
    score = float(model.decision_function(X)[0])  # higher = more normal
    return {
        "prediction": "Benign" if pred == 1 else "Anomaly",
        "anomaly_score": score,
        "confidence": float(np.clip(abs(score) / 0.2, 0.0, 1.0)),
    }


def predict_batch(df: pd.DataFrame, model_path: str | Path = MODEL_PATH) -> pd.DataFrame:
    """Scores a DataFrame of flows; adds prediction and anomaly_score columns."""
    model, scaler, feature_cols = load_artifacts(model_path)
    X = scaler.transform(df[feature_cols].values)
    preds = model.predict(X)
    scores = model.decision_function(X)
    df = df.copy()
    df["prediction"] = ["Benign" if p == 1 else "Anomaly" for p in preds]
    df["anomaly_score"] = scores
    return df
