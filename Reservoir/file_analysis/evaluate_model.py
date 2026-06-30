#!/usr/bin/env python3
"""Evaluate the Reservoir file-analysis MVP model on labeled sample folders."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import joblib

from Reservoir.file_analysis.feature_extractor_dataset import iter_candidate_files, parse_elf
from Reservoir.file_analysis.predictor import suspicious_evidence, to_float


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "path",
            "filename",
            "expected_label",
            "expected_class",
            "predicted_label",
            "predicted_class",
            "suspicious_probability",
            "correct",
            "heuristic_score",
            "evidence_strings",
            "evidence_imports",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def class_name(label: int) -> str:
    return "suspicious" if label == 1 else "clean"


def evaluate(args: argparse.Namespace) -> None:
    model = joblib.load(args.model)
    columns_payload = json.loads(Path(args.feature_columns).read_text(encoding="utf-8"))
    columns = columns_payload["feature_columns"]

    labeled_dirs = [(Path(args.clean_dir), 0), (Path(args.suspicious_dir), 1)]
    rows: list[dict[str, Any]] = []

    for directory, expected_label in labeled_dirs:
        for path in iter_candidate_files(directory):
            result = parse_elf(path, keep_raw=False)
            features = result["features"]
            x = [[to_float(features.get(col, 0.0)) for col in columns]]
            predicted_label = int(model.predict(x)[0])

            probability = None
            if hasattr(model, "predict_proba"):
                classes = list(model.classes_)
                if 1 in classes:
                    probability = float(model.predict_proba(x)[0][classes.index(1)])

            evidence = suspicious_evidence(features)
            rows.append({
                "path": str(path),
                "filename": path.name,
                "expected_label": expected_label,
                "expected_class": class_name(expected_label),
                "predicted_label": predicted_label,
                "predicted_class": class_name(predicted_label),
                "suspicious_probability": "" if probability is None else round(probability, 6),
                "correct": int(predicted_label == expected_label),
                "heuristic_score": features.get("heuristic_score"),
                "evidence_strings": ",".join(evidence["strings"]),
                "evidence_imports": ",".join(evidence["imports"]),
            })

    if not rows:
        raise RuntimeError("No sample files found to evaluate")

    total = len(rows)
    correct = sum(int(row["correct"]) for row in rows)
    clean_total = sum(1 for row in rows if row["expected_label"] == 0)
    suspicious_total = sum(1 for row in rows if row["expected_label"] == 1)
    confusion = {
        "clean_as_clean": sum(1 for row in rows if row["expected_label"] == 0 and row["predicted_label"] == 0),
        "clean_as_suspicious": sum(1 for row in rows if row["expected_label"] == 0 and row["predicted_label"] == 1),
        "suspicious_as_clean": sum(1 for row in rows if row["expected_label"] == 1 and row["predicted_label"] == 0),
        "suspicious_as_suspicious": sum(1 for row in rows if row["expected_label"] == 1 and row["predicted_label"] == 1),
    }
    summary = {
        "total": total,
        "correct": correct,
        "accuracy": round(correct / total, 6),
        "clean_total": clean_total,
        "suspicious_total": suspicious_total,
        "confusion": confusion,
        "note": "Evaluation is on the tiny synthetic MVP sample set, not a real-world malware benchmark.",
    }

    write_csv(Path(args.output_csv), rows)
    write_json(Path(args.output_json), summary)

    print(f"Saved prediction table to {args.output_csv}")
    print(f"Saved summary to {args.output_json}")
    print(f"Accuracy on MVP samples: {correct}/{total} = {summary['accuracy']:.3f}")
    for row in rows:
        mark = "OK" if row["correct"] else "FAIL"
        print(
            f"{mark} {row['filename']}: expected={row['expected_class']} "
            f"predicted={row['predicted_class']} p_suspicious={row['suspicious_probability']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Reservoir file-analysis MVP model")
    parser.add_argument("--clean-dir", default="samples/clean")
    parser.add_argument("--suspicious-dir", default="samples/suspicious")
    parser.add_argument("--model", default="models/file_analysis_baseline.joblib")
    parser.add_argument("--feature-columns", default="models/file_analysis_feature_columns.json")
    parser.add_argument("--output-csv", default="output/model_test_predictions.csv")
    parser.add_argument("--output-json", default="output/model_test_summary.json")
    args = parser.parse_args()
    evaluate(args)


if __name__ == "__main__":
    main()
