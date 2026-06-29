import joblib
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "models" / "model.pkl"


def load_artifacts(model_path: str | Path = MODEL_PATH) -> tuple:
    """model.pkl içinden model, scaler ve label_encoder'ı yükler."""
    artifacts = joblib.load(model_path)
    return artifacts["model"], artifacts["scaler"], artifacts["label_encoder"], artifacts["feature_cols"]


def predict_single(row: dict, model_path: str | Path = MODEL_PATH) -> dict:
    """Tek bir bağlantı kaydı için tahmin yapar."""
    model, scaler, label_encoder, feature_cols = load_artifacts(model_path)
    df = pd.DataFrame([row])[feature_cols]
    X = scaler.transform(df.values)
    pred_idx = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    label = label_encoder.inverse_transform([pred_idx])[0]
    return {
        "prediction": label,
        "confidence": float(proba.max()),
        "probabilities": dict(zip(label_encoder.classes_, proba.tolist())),
    }


def predict_batch(df: pd.DataFrame, model_path: str | Path = MODEL_PATH) -> pd.DataFrame:
    """Bir DataFrame üzerinde batch tahmin yapar; sonuçları yeni sütun olarak ekler."""
    model, scaler, label_encoder, feature_cols = load_artifacts(model_path)
    X = scaler.transform(df[feature_cols].values)
    preds = model.predict(X)
    probas = model.predict_proba(X).max(axis=1)
    df = df.copy()
    df["prediction"] = label_encoder.inverse_transform(preds)
    df["confidence"] = probas
    return df
