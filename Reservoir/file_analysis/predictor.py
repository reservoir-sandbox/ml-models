#!/usr/bin/env python3
"""Reusable prediction helpers for Reservoir static ELF analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib

from Reservoir.file_analysis.feature_extractor_dataset import (
    SUSPICIOUS_IMPORTS,
    SUSPICIOUS_STRING_PATTERNS,
    parse_elf,
)


DEFAULT_MODEL_PATH = Path("models/file_analysis_baseline.joblib")
DEFAULT_FEATURE_COLUMNS_PATH = Path("models/file_analysis_feature_columns.json")


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


def load_feature_columns(path: str | Path = DEFAULT_FEATURE_COLUMNS_PATH) -> list[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return list(payload["feature_columns"])


def features_to_matrix(features: dict[str, Any], columns: list[str]) -> list[list[float]]:
    return [[to_float(features.get(col, 0.0)) for col in columns]]


def build_prediction_output(
    *,
    input_path: str | Path,
    model: Any,
    columns: list[str],
    features: dict[str, Any],
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    x = features_to_matrix(features, columns)
    predicted_label = int(model.predict(x)[0])
    probability = None

    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if 1 in classes:
            probability = float(model.predict_proba(x)[0][classes.index(1)])

    output: dict[str, Any] = {
        "input": str(input_path),
        "sha256": features.get("sha256"),
        "is_elf": bool(features.get("is_elf")),
        "predicted_label": predicted_label,
        "predicted_class": "suspicious" if predicted_label == 1 else "clean",
        "suspicious_probability": probability,
        "heuristic_score": features.get("heuristic_score"),
        "evidence": suspicious_evidence(features),
        "features": features,
    }
    if raw is not None:
        output["raw"] = raw
    return output


def predict_elf(
    input_path: str | Path,
    *,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    feature_columns_path: str | Path = DEFAULT_FEATURE_COLUMNS_PATH,
    keep_raw: bool = False,
) -> dict[str, Any]:
    model = joblib.load(model_path)
    columns = load_feature_columns(feature_columns_path)
    result = parse_elf(Path(input_path), keep_raw=keep_raw)
    return build_prediction_output(
        input_path=input_path,
        model=model,
        columns=columns,
        features=result["features"],
        raw=result["raw"] if keep_raw else None,
    )
