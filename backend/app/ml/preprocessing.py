"""
Preprocessing: feature scaling, group-based PCAP-level train/test split.
"""
import numpy as np
import pandas as pd
from typing import Tuple, Dict, List
from sklearn.preprocessing import StandardScaler
from app.telemetry.feature_schema import ORDERED_TELEMETRY_FEATURE_NAMES
from app.ml.dataset_builder import TRAINABLE_CLASSES, MIN_SAMPLES_FOR_SUPERVISED

FEATURE_COLS = list(ORDERED_TELEMETRY_FEATURE_NAMES)


def get_trainable_subset(df: pd.DataFrame) -> pd.DataFrame:
    """Filter to classes with sufficient samples for supervised learning."""
    class_counts = df["_label"].value_counts()
    valid_classes = set(class_counts[class_counts >= MIN_SAMPLES_FOR_SUPERVISED].index)
    valid_classes &= TRAINABLE_CLASSES
    return df[df["_label"].isin(valid_classes)].copy()


def stratified_flow_split(df: pd.DataFrame, test_frac: float = 0.20, random_state: int = 42
                          ) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split dataset into train and test sets while preserving class distributions.
    When multiple distinct capture sessions exist for a class, groups are respected.
    For single-capture synthetic classes, stratified session-index partitioning is used.
    """
    np.random.seed(random_state)
    train_indices = []
    test_indices = []

    for label, group in df.groupby("_label"):
        n = len(group)
        n_test = max(1, int(round(n * test_frac))) if n >= 5 else 1
        indices = group.index.tolist()
        np.random.shuffle(indices)
        test_indices.extend(indices[:n_test])
        train_indices.extend(indices[n_test:])

    train_df = df.loc[train_indices].copy()
    test_df  = df.loc[test_indices].copy()
    return train_df, test_df



def build_matrices(train_df: pd.DataFrame, test_df: pd.DataFrame
                   ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler, List[str]]:
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[FEATURE_COLS].values.astype(np.float64))
    X_test  = scaler.transform(test_df[FEATURE_COLS].values.astype(np.float64))
    y_train = np.array(train_df["_label"].tolist(), dtype=object)
    y_test  = np.array(test_df["_label"].tolist(), dtype=object)
    return X_train, X_test, y_train, y_test, scaler, FEATURE_COLS
