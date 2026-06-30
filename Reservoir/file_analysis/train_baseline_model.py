#!/usr/bin/env python3
"""Train the Reservoir file-analysis model from extracted ELF features."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


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


def load_all_rows(input_csv: Path, extra_csvs: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    sources = [str(input_csv)]
    rows = load_rows(input_csv)
    for extra_csv in extra_csvs:
        extra_path = Path(extra_csv)
        rows.extend(load_rows(extra_path))
        sources.append(str(extra_path))
    return rows, sources


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


def candidate_models(random_state: int) -> dict[str, Pipeline]:
    return {
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=300,
                max_depth=10,
                min_samples_leaf=1,
                random_state=random_state,
                class_weight="balanced",
            )),
        ]),
        "extra_trees": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", ExtraTreesClassifier(
                n_estimators=400,
                max_depth=None,
                min_samples_leaf=1,
                random_state=random_state,
                class_weight="balanced",
            )),
        ]),
        "gradient_boosting": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", GradientBoostingClassifier(random_state=random_state)),
        ]),
        "logistic_regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=random_state,
            )),
        ]),
    }


def choose_model(
    x: list[list[float]],
    y: list[int],
    *,
    random_state: int,
) -> tuple[str, Pipeline, dict[str, dict[str, float]]]:
    counts = Counter(y)
    folds = min(5, min(counts.values()))
    candidates = candidate_models(random_state)
    scores: dict[str, dict[str, float]] = {}

    if folds >= 2:
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=random_state)
        for name, pipeline in candidates.items():
            values = cross_val_score(pipeline, x, y, cv=cv, scoring="balanced_accuracy")
            scores[name] = {
                "cv_balanced_accuracy_mean": round(float(values.mean()), 6),
                "cv_balanced_accuracy_std": round(float(values.std()), 6),
            }
        best_name = max(scores, key=lambda name: scores[name]["cv_balanced_accuracy_mean"])
    else:
        # Very small fallback: train candidates on all rows and prefer the tree ensemble.
        for name in candidates:
            scores[name] = {"cv_balanced_accuracy_mean": 0.0, "cv_balanced_accuracy_std": 0.0}
        best_name = "extra_trees"

    return best_name, candidates[best_name], scores


def model_importances(pipeline: Pipeline, columns: list[str]) -> list[float] | None:
    model = pipeline.named_steps["model"]
    if hasattr(model, "feature_importances_"):
        return list(model.feature_importances_)
    if hasattr(model, "coef_"):
        coefficients = list(model.coef_[0])
        return [abs(float(value)) for value in coefficients]
    return None


def train(args: argparse.Namespace) -> None:
    rows, sources = load_all_rows(Path(args.input_csv), args.extra_csv)
    if not rows:
        raise RuntimeError("No rows found in dataset CSV")

    labels = [int(row["label"]) for row in rows]
    counts = Counter(labels)
    if len(counts) < 2:
        raise RuntimeError("Need both clean label=0 and suspicious label=1 rows")

    columns = feature_columns(rows)
    x = matrix(rows, columns)
    y = labels

    selected_name, selected_pipeline, candidate_scores = choose_model(x, y, random_state=args.random_state)

    can_split = len(rows) >= 8 and min(counts.values()) >= 2
    metrics: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(args.input_csv),
        "dataset_sources": sources,
        "rows": len(rows),
        "label_counts": {str(k): v for k, v in sorted(counts.items())},
        "feature_count": len(columns),
        "selected_model": selected_name,
        "candidate_scores": candidate_scores,
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
        selected_pipeline.fit(x_train, y_train)
        predictions = selected_pipeline.predict(x_test)
        metrics.update({
            "train_rows": len(x_train),
            "test_rows": len(x_test),
            "accuracy": accuracy_score(y_test, predictions),
            "balanced_accuracy": balanced_accuracy_score(y_test, predictions),
            "f1_suspicious": f1_score(y_test, predictions, pos_label=1, zero_division=0),
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
        selected_pipeline.fit(x, y)
        metrics["warning"] = "Dataset too small for a stratified holdout split; trained on all rows."

    # Fit the selected final model on all available rows after computing holdout metrics.
    selected_pipeline.fit(x, y)

    Path(args.model_output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(selected_pipeline, args.model_output)
    write_json(Path(args.feature_columns_output), {
        "feature_columns": columns,
        "selected_model": selected_name,
    })
    write_json(Path(args.metrics_output), metrics)

    importances = model_importances(selected_pipeline, columns)
    if importances is not None:
        write_importance(Path(args.importance_output), columns, importances)

    print(f"Saved model to {args.model_output}")
    print(f"Saved feature columns to {args.feature_columns_output}")
    print(f"Saved metrics to {args.metrics_output}")
    print(f"Saved feature importances to {args.importance_output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Reservoir file-analysis model")
    parser.add_argument("--input-csv", default="data/features.csv")
    parser.add_argument("--extra-csv", action="append", default=[], help="Optional extra feature CSV with the same label/features schema")
    parser.add_argument("--model-output", default="models/file_analysis_baseline.joblib")
    parser.add_argument("--feature-columns-output", default="models/file_analysis_feature_columns.json")
    parser.add_argument("--metrics-output", default="data/file_analysis_model_metrics.json")
    parser.add_argument("--importance-output", default="data/file_analysis_feature_importance.csv")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
