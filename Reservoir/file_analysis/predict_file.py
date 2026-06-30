#!/usr/bin/env python3
"""Run the Reservoir file-analysis MVP model on one ELF file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from Reservoir.file_analysis.predictor import predict_elf


def predict(args: argparse.Namespace) -> None:
    output = predict_elf(
        args.input,
        model_path=args.model,
        feature_columns_path=args.feature_columns,
        keep_raw=args.keep_raw,
    )

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
