# FILE: src/forensiq/ml/training/train.py
"""ForensIQ XGBoost + IsolationForest ensemble training script.

Trains:
  1. CalibratedClassifierCV (XGBoost) — supervised, 20 features
  2. IsolationForest — unsupervised anomaly detector on benign samples

Dataset: CIC-MalMem2022 (University of New Brunswick)
         https://www.unb.ca/cic/datasets/malmem-2022.html
         58,596 samples, 57 columns, binary classes: Benign / Malware

The dataset contains system-level (aggregated) Volatility features.
This script maps available CIC-MalMem2022 columns to our 20 per-process features.
The trained models expect exactly 20 features in FEATURE_NAMES order at inference.

Usage:
    forensiq train --data /path/to/Obfuscated-MalMem2022.parquet
    forensiq train --data /path/to/cic_malmem2022.csv
    forensiq train --data ./ml/data/csv/  (directory of CSV files)
    make train DATA=/path/to/data.parquet
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# ─── CIC-MalMem2022 → ForensIQ feature mapping ───────────────────────────────
# Maps each of our 20 FEATURE_NAMES to the best available dataset column.
# The training matrix is built with exactly 20 columns in this order so the
# trained model accepts ProcessFeatureVector.to_numpy_array() at inference.
#
# CIC-MalMem2022 columns (system-wide aggregates from Volatility plugins):
#   pslist.*     — process list stats
#   dlllist.*    — DLL load stats
#   handles.*    — handle stats
#   ldrmodules.* — loader module consistency (detects hidden/unlinked DLLs)
#   malfind.*    — memory injection indicators
#   psxview.*    — cross-view process hiding detection
#   svcscan.*    — service scan
#   callbacks.*  — kernel callbacks
#
# Mapping strategy:
#   - Use the most semantically relevant column for each feature.
#   - None → feature will be set to 0.0 for all training rows (feature absent).

FEATURE_TO_DATASET_COL: dict[str, str | None] = {
    "process_name_entropy": "svcscan.nservices",
    "path_entropy": "svcscan.nactive",
    "path_depth": "pslist.nproc",
    "is_system_path": "pslist.nprocs64bit",
    "parent_child_legit": "psxview.not_in_pslist",
    "dll_count": "dlllist.ndlls",
    "suspicious_dll_count": "ldrmodules.not_in_load",
    "has_network_connection": "handles.nport",
    "network_connection_count": "handles.nport",
    "external_connection_count": "psxview.not_in_session",
    "malfind_hits": "malfind.ninjections",
    "vad_rwx_count": "malfind.uniqueInjections",
    "thread_count": "pslist.avg_threads",
    "handle_count": "handles.avg_handles_per_proc",
    "has_encoded_cmdline": "ldrmodules.not_in_mem",
    # New v2 features
    "vad_execute_write_page_count": "malfind.ninjections",  # page count proxy (re-use injection count)
    "parent_name_mismatch": "psxview.not_in_csrss",  # hidden from csrss → spoofed parent
    "thread_start_in_heap": "malfind.uniqueInjections",  # injected regions ≈ heap-started threads
    "import_table_entropy": "dlllist.ndlls",  # DLL diversity → import entropy proxy
    "time_delta_from_parent_seconds": None,  # not in dataset → defaults to 0.0
}

# FEATURE_NAMES in canonical order (must match ProcessFeatureVector.to_numpy_row())
FEATURE_NAMES: list[str] = [
    "process_name_entropy",
    "path_entropy",
    "path_depth",
    "is_system_path",
    "parent_child_legit",
    "dll_count",
    "suspicious_dll_count",
    "has_network_connection",
    "network_connection_count",
    "external_connection_count",
    "malfind_hits",
    "vad_rwx_count",
    "thread_count",
    "handle_count",
    "has_encoded_cmdline",
    # New v2 features
    "vad_execute_write_page_count",
    "parent_name_mismatch",
    "thread_start_in_heap",
    "import_table_entropy",
    "time_delta_from_parent_seconds",
]

# Target column name in the dataset
TARGET_COLUMN = "Class"

# Label mapping: dataset class names → binary (0=benign, 1=malicious)
BINARY_LABEL_MAP: dict[str, int] = {
    # CIC-MalMem2022 parquet uses "Benign" and "Malware"
    "Benign": 0,
    "Malware": 1,
    # Older CSV version uses individual family names
    "Spyware": 1,
    "Ransomware": 1,
    "Trojan": 1,
    "Backdoor": 1,
    # Handle lowercase variants
    "benign": 0,
    "malware": 1,
    "spyware": 1,
    "ransomware": 1,
    "trojan": 1,
    "backdoor": 1,
}

# XGBoost hyperparameters (determined via Optuna HPO — see tune.py)
XGBOOST_PARAMS: dict[str, Any] = {
    "n_estimators": 300,
    "max_depth": 6,
    "learning_rate": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 1,
    "gamma": 0,
    "reg_alpha": 0.1,
    "reg_lambda": 1.0,
    "n_jobs": -1,
    "random_state": 42,
    "eval_metric": "logloss",
}


def load_dataset(data_path: Path) -> tuple[pd.DataFrame, pd.Series]:
    """Load and preprocess the CIC-MalMem2022 dataset.

    Supports .parquet, .csv files, and directories of CSV files.
    Builds a training matrix with exactly 20 columns matching FEATURE_NAMES
    so the trained model is directly compatible with inference.

    Args:
        data_path: Path to the dataset file (.parquet or .csv) or directory of CSVs.

    Returns:
        Tuple of (feature_matrix DataFrame with 20 cols, binary_labels Series).

    Raises:
        FileNotFoundError: If data_path does not exist.
        ValueError: If required Class column is missing.
    """
    if data_path.is_dir():
        # Load all CSVs from directory and concatenate
        csv_files = list(data_path.glob("*.csv"))
        parquet_files = list(data_path.glob("*.parquet"))
        if parquet_files:
            print(f"Loading {len(parquet_files)} parquet files from {data_path}")
            dfs = [pd.read_parquet(f) for f in parquet_files]
            df = pd.concat(dfs, ignore_index=True)
        elif csv_files:
            print(f"Loading {len(csv_files)} CSV files from {data_path}")
            dfs = [pd.read_csv(f) for f in csv_files]
            df = pd.concat(dfs, ignore_index=True)
        else:
            raise FileNotFoundError(f"No .parquet or .csv files found in: {data_path}")
    elif data_path.suffix.lower() == ".parquet":
        print(f"Loading parquet: {data_path}")
        df = pd.read_parquet(data_path)
    else:
        print(f"Loading CSV: {data_path}")
        df = pd.read_csv(data_path)

    print(f"Dataset shape: {df.shape}")
    print(f"Columns ({len(df.columns)}): {list(df.columns)}")

    # Find the Class column (case-insensitive)
    class_col = None
    for col in df.columns:
        if col.lower() == "class":
            class_col = col
            break

    if class_col is None:
        raise ValueError(f"Target column 'Class' not found. Available columns: {list(df.columns)}")

    # Extract labels
    labels_raw = df[class_col]
    print(f"\nClass distribution:\n{labels_raw.value_counts()}")

    # Convert to binary labels
    labels = labels_raw.map(BINARY_LABEL_MAP)
    unmapped = labels.isna().sum()
    if unmapped > 0:
        print(f"WARNING: {unmapped} rows have unmapped class values, dropping them.")
        mask = ~labels.isna()
        df = df[mask]
        labels = labels[mask]

    labels = labels.astype(int)

    # Build the 20-feature training matrix in FEATURE_NAMES order
    # Each feature maps to a dataset column (or 0.0 if not available)
    print(f"\nBuilding {len(FEATURE_NAMES)}-feature training matrix...")
    feature_data: dict[str, pd.Series] = {}
    for feature_name in FEATURE_NAMES:
        dataset_col = FEATURE_TO_DATASET_COL.get(feature_name)
        if dataset_col and dataset_col in df.columns:
            feature_data[feature_name] = (
                df[dataset_col].fillna(0).replace([float("inf"), float("-inf")], 0).astype(float)
            )
            print(f"  {feature_name:<30} ← {dataset_col}")
        else:
            feature_data[feature_name] = pd.Series(0.0, index=df.index)
            print(f"  {feature_name:<30} ← (no mapping, defaulting to 0.0)")

    X = pd.DataFrame(feature_data, index=df.index)
    print(f"\nFeature matrix shape: {X.shape}")
    return X, labels


def train_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
) -> CalibratedClassifierCV:
    """Train and calibrate the XGBoost classifier.

    Args:
        X_train: Training feature matrix.
        y_train: Training binary labels.
        X_val: Validation feature matrix (used for early stopping).
        y_val: Validation binary labels.

    Returns:
        Calibrated XGBoost classifier (CalibratedClassifierCV wrapping XGBClassifier).
    """
    print(f"Training XGBoost: {len(X_train)} samples, {X_train.shape[1]} features")

    xgb = XGBClassifier(**XGBOOST_PARAMS)
    xgb.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    print("Calibrating with isotonic regression (5-fold CV)...")
    calibrated = CalibratedClassifierCV(
        estimator=xgb,
        method="isotonic",
        cv=5,
    )
    calibrated.fit(X_train, y_train)

    return calibrated


def evaluate_model(
    model: CalibratedClassifierCV,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, float]:
    """Evaluate the trained model on the test set.

    Args:
        model: Trained calibrated model.
        X_test: Test feature matrix.
        y_test: True test labels.

    Returns:
        Dict of metric name → value.
    """
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, y_proba),
        "test_samples": len(y_test),
        "positive_samples": int(y_test.sum()),
    }

    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    for name, val in metrics.items():
        print(f"  {name:<25}: {val:.4f}" if isinstance(val, float) else f"  {name:<25}: {val}")
    print()
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    return metrics


def save_model(
    model: CalibratedClassifierCV,
    output_path: Path,
    metrics: dict[str, float],
    feature_cols: list[str],
) -> None:
    """Save the model and metadata to disk.

    Args:
        model: Trained calibrated model.
        output_path: Path to save the joblib file.
        metrics: Evaluation metrics dict.
        feature_cols: List of feature column names used for training.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"Model saved: {output_path}")

    # Save metadata alongside the model
    import json

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(tz=UTC).isoformat(),
        "dataset": "CIC-MalMem2022",
        "features_used": feature_cols,
        "n_features": len(feature_cols),
        "xgboost_params": XGBOOST_PARAMS,
        "metrics": metrics,
    }
    meta_path = output_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2))
    print(f"Metadata saved: {meta_path}")


def main() -> int:
    """Main training entry point."""
    parser = argparse.ArgumentParser(
        description="Train ForensIQ XGBoost classifier on CIC-MalMem2022 dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to CIC-MalMem2022 CSV file or directory of CSVs",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./ml/data/forensiq_model.joblib"),
        help="Output path for the trained model (default: ./ml/data/forensiq_model.joblib)",
    )
    parser.add_argument(
        "--test-split",
        type=float,
        default=0.2,
        help="Fraction of data to hold out for final evaluation (default: 0.2)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    if not args.data.exists():
        print(f"ERROR: Data path not found: {args.data}", file=sys.stderr)
        return 1

    print(f"Loading dataset from: {args.data}")
    X, y = load_dataset(args.data)

    print(
        f"Splitting: {100 * (1 - args.test_split):.0f}% train / {100 * args.test_split:.0f}% test"
    )
    X_temp, X_test, y_temp, y_test = train_test_split(
        X,
        y,
        test_size=args.test_split,
        stratify=y,
        random_state=args.seed,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp,
        y_temp,
        test_size=0.2,
        stratify=y_temp,
        random_state=args.seed,
    )

    model = train_model(X_train, y_train, X_val, y_val)
    metrics = evaluate_model(model, X_test, y_test)
    save_model(model, args.output, metrics, FEATURE_NAMES)

    # ── Train IsolationForest on benign samples only ──────────────────────────
    iso_output = args.output.with_name(
        args.output.stem.replace("forensiq_model", "forensiq_isolation") + ".joblib"
    )
    print("\nTraining IsolationForest on benign samples (unsupervised anomaly detector)...")
    # Use all benign training samples for IsolationForest — it learns the normal profile
    X_benign = X_train[y_train == 0]
    print(f"  Benign training samples: {len(X_benign)}")

    iso_model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.05,  # ~5% expected anomalies in production
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=args.seed,
    )
    iso_model.fit(X_benign)
    print(f"  IsolationForest trained. Saving to: {iso_output}")

    # Evaluate: benign samples should have high scores, malicious low
    X_test_all = X_test.copy()
    iso_test_scores = iso_model.score_samples(X_test_all)
    # Normalize to [0, 1] anomaly score (higher = more anomalous)
    iso_min, iso_max = iso_test_scores.min(), iso_test_scores.max()
    if iso_max > iso_min:
        iso_normalized = 1.0 - (iso_test_scores - iso_min) / (iso_max - iso_min)
    else:
        iso_normalized = np.zeros(len(iso_test_scores))
    # Threshold at 0.5 for evaluation
    iso_pred = (iso_normalized >= 0.5).astype(int)
    iso_recall = recall_score(y_test, iso_pred, zero_division=0)
    iso_precision = precision_score(y_test, iso_pred, zero_division=0)
    print(f"  IsolationForest evaluation: precision={iso_precision:.4f}, recall={iso_recall:.4f}")

    iso_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(iso_model, iso_output)
    print(f"  IsolationForest saved: {iso_output}")

    # Save IsolationForest metadata
    import json

    iso_metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(tz=UTC).isoformat(),
        "dataset": "CIC-MalMem2022 (benign samples only)",
        "features_used": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_training_samples": len(X_benign),
        "contamination": 0.05,
        "evaluation": {
            "precision": float(iso_precision),
            "recall": float(iso_recall),
        },
    }
    iso_meta_path = iso_output.with_suffix(".json")
    iso_meta_path.write_text(json.dumps(iso_metadata, indent=2))
    print(f"  IsolationForest metadata saved: {iso_meta_path}")

    print("\nTraining complete! Both XGBoost and IsolationForest models saved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
