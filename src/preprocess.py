import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

LABEL_COL = "Label"
DROP_COLS = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Traffic Type", "Traffic Subtype"]
CATEGORICAL_COLS = ["Protocol"]


def load_data(train_path: str, test_path: str | None = None) -> pd.DataFrame | tuple:
    train_df = pd.read_csv(train_path, low_memory=False)
    if test_path:
        test_df = pd.read_csv(test_path, low_memory=False)
        return train_df, test_df
    return train_df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    return df


def encode_categoricals(df: pd.DataFrame, encoders: dict | None = None) -> tuple[pd.DataFrame, dict]:
    if encoders is None:
        encoders = {}
    for col in CATEGORICAL_COLS:
        if col not in df.columns:
            continue
        if col not in encoders:
            encoders[col] = LabelEncoder()
            df[col] = encoders[col].fit_transform(df[col].astype(str))
        else:
            df[col] = encoders[col].transform(df[col].astype(str))
    return df, encoders


def encode_labels(y: pd.Series, encoder: LabelEncoder | None = None) -> tuple[np.ndarray, LabelEncoder]:
    if encoder is None:
        encoder = LabelEncoder()
        return encoder.fit_transform(y), encoder
    return encoder.transform(y), encoder


def preprocess(
    train_path: str,
    test_path: str | None = None,
    label_col: str = LABEL_COL,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple:
    """
    Load, clean, encode, and scale the dataset.

    Returns: (X_train, X_test, y_train, y_test, scaler, label_encoder, feature_names)
    """
    if test_path:
        train_df, test_df = load_data(train_path, test_path)
        train_df = clean(train_df)
        test_df = clean(test_df)

        train_df, encoders = encode_categoricals(train_df)
        test_df, _ = encode_categoricals(test_df, encoders)

        feature_cols = [c for c in train_df.columns if c != label_col]
        X_train = train_df[feature_cols].values
        X_test = test_df[feature_cols].values
        y_train_raw = train_df[label_col]
        y_test_raw = test_df[label_col]
    else:
        df = load_data(train_path)
        df = clean(df)
        df, _ = encode_categoricals(df)

        feature_cols = [c for c in df.columns if c != label_col]
        X = df[feature_cols].values
        y_raw = df[label_col]
        X_train, X_test, y_train_raw, y_test_raw = train_test_split(
            X, y_raw, test_size=test_size, random_state=random_state, stratify=y_raw
        )

    y_train, label_encoder = encode_labels(y_train_raw)
    y_test, _ = encode_labels(y_test_raw, label_encoder)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, scaler, label_encoder, feature_cols
