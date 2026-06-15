#!/usr/bin/env python3
"""Train the first Reservoir file-analysis MVP model from extracted ELF features."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


NON_FEATURE_COLUMNS = {"label", "path", "filename", "sha256"}


def to_float(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def feature_columns(rows: list[dict[str, str]]) -> list[str]:
    columns: set[str] = set()
    for row in rows:
        columns.update(row.keys())
    return sorted(col for col in columns if col not in NON_FEATURE_COLUMNS)


def matrix(rows: list[dict[str, str]], columns: list[str]) -> list[list[float]]:
    return [[to_float(row.get(col, 0.0)) for col in columns] for row in rows]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_importance(path: Path, columns: list[str], importances: list[float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pairs = sorted(zip(columns, importances), key=lambda item: item[1], reverse=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["feature", "importance"])
        writer.writerows((name, f"{score:.8f}") for name, score in pairs)


def train(args: argparse.Namespace) -> None:
    rows = load_rows(Path(args.input_csv))
    if not rows:
        raise RuntimeError("No rows found in dataset CSV")

    labels = [int(row["label"]) for row in rows]
    counts = Counter(labels)
    if len(counts) < 2:
        raise RuntimeError("Need both clean label=0 and suspicious label=1 rows")

    columns = feature_columns(rows)
    x = matrix(rows, columns)
    y = labels

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            random_state=args.random_state,
            class_weight="balanced",
        )),
    ])

    can_split = len(rows) >= 8 and min(counts.values()) >= 2
    metrics: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(args.input_csv),
        "rows": len(rows),
        "label_counts": {str(k): v for k, v in sorted(counts.items())},
        "feature_count": len(columns),
        "note": "MVP model trained on synthetic suspicious samples; do not treat metrics as real-world malware performance.",
    }

    if can_split:
        x_train, x_test, y_train, y_test = train_test_split(
            x,
            y,
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=y,
        )
        pipeline.fit(x_train, y_train)
        predictions = pipeline.predict(x_test)
        metrics.update({
            "train_rows": len(x_train),
            "test_rows": len(x_test),
            "accuracy": accuracy_score(y_test, predictions),
            "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
            "classification_report": classification_report(
                y_test,
                predictions,
                labels=[0, 1],
                target_names=["clean", "suspicious"],
                output_dict=True,
                zero_division=0,
            ),
        })
    else:
        pipeline.fit(x, y)
        metrics["warning"] = "Dataset too small for a stratified holdout split; trained on all rows."

    Path(args.model_output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, args.model_output)
    write_json(Path(args.feature_columns_output), {"feature_columns": columns})
    write_json(Path(args.metrics_output), metrics)

    model = pipeline.named_steps["model"]
    if hasattr(model, "feature_importances_"):
        write_importance(Path(args.importance_output), columns, list(model.feature_importances_))

    print(f"Saved model to {args.model_output}")
    print(f"Saved feature columns to {args.feature_columns_output}")
    print(f"Saved metrics to {args.metrics_output}")
    print(f"Saved feature importances to {args.importance_output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Reservoir file-analysis baseline model")
    parser.add_argument("--input-csv", default="data/features.csv")
    parser.add_argument("--model-output", default="models/file_analysis_baseline.joblib")
    parser.add_argument("--feature-columns-output", default="models/file_analysis_feature_columns.json")
    parser.add_argument("--metrics-output", default="data/file_analysis_model_metrics.json")
    parser.add_argument("--importance-output", default="data/file_analysis_feature_importance.csv")
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
