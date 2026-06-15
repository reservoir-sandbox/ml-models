#!/usr/bin/env python3
"""Run the Reservoir file-analysis MVP model on one ELF file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib

from Reservoir.file_analysis.feature_extractor_dataset import (
    SUSPICIOUS_IMPORTS,
    SUSPICIOUS_STRING_PATTERNS,
    parse_elf,
)


def to_float(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def suspicious_evidence(features: dict[str, Any]) -> dict[str, list[str]]:
    strings = sorted(
        name.removeprefix("has_str_")
        for name in SUSPICIOUS_STRING_PATTERNS
        if int(features.get(name, 0)) == 1
    )
    imports = sorted(
        name
        for name in SUSPICIOUS_IMPORTS
        if int(features.get(f"has_import_{name}", 0)) == 1
    )
    return {"strings": strings, "imports": imports}


def predict(args: argparse.Namespace) -> None:
    model = joblib.load(args.model)
    columns_payload = json.loads(Path(args.feature_columns).read_text(encoding="utf-8"))
    columns = columns_payload["feature_columns"]

    result = parse_elf(Path(args.input), keep_raw=args.keep_raw)
    features = result["features"]
    x = [[to_float(features.get(col, 0.0)) for col in columns]]

    predicted_label = int(model.predict(x)[0])
    probability = None
    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if 1 in classes:
            probability = float(model.predict_proba(x)[0][classes.index(1)])

    output = {
        "input": str(args.input),
        "sha256": features.get("sha256"),
        "is_elf": bool(features.get("is_elf")),
        "predicted_label": predicted_label,
        "predicted_class": "suspicious" if predicted_label == 1 else "clean",
        "suspicious_probability": probability,
        "heuristic_score": features.get("heuristic_score"),
        "evidence": suspicious_evidence(features),
        "features": features,
    }
    if args.keep_raw:
        output["raw"] = result["raw"]

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Saved prediction to {args.output}")
    else:
        print(json.dumps(output, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict clean/suspicious class for one ELF")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model", default="models/file_analysis_baseline.joblib")
    parser.add_argument("--feature-columns", default="models/file_analysis_feature_columns.json")
    parser.add_argument("--output")
    parser.add_argument("--keep-raw", action="store_true")
    args = parser.parse_args()
    predict(args)


if __name__ == "__main__":
    main()
