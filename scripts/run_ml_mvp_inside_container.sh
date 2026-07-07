#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  file \
  python3 \
  python3-pip

python3 -m pip install --no-cache-dir -r requirements.txt

bash scripts/build_clean_samples.sh
bash build_suspicious_samples.sh

python3 -m Reservoir.file_analysis.feature_extractor_dataset build-dataset \
  --clean-dir samples/clean \
  --suspicious-dir samples/suspicious \
  --output-csv data/features.csv \
  --output-jsonl data/features.jsonl \
  --keep-raw

python3 -m Reservoir.file_analysis.train_baseline_model \
  --input-csv data/features.csv \
  --model-output models/file_analysis_baseline.joblib \
  --feature-columns-output models/file_analysis_feature_columns.json \
  --model-metadata-output models/file_analysis_model_metadata.json \
  --metrics-output data/file_analysis_model_metrics.json \
  --importance-output data/file_analysis_feature_importance.csv

python3 -m Reservoir.file_analysis.predict_file \
  --input samples/suspicious/fake_combo \
  --model models/file_analysis_baseline.joblib \
  --feature-columns models/file_analysis_feature_columns.json \
  --output output/fake_combo_prediction.json

echo
echo "Compiled ELF files:"
file samples/clean/* samples/suspicious/*

echo
echo "MVP artifacts:"
ls -lh data/features.csv \
       data/features.jsonl \
       data/file_analysis_model_metrics.json \
       data/file_analysis_feature_importance.csv \
       models/file_analysis_baseline.joblib \
       models/file_analysis_model_metadata.json \
       models/file_analysis_feature_columns.json \
       output/fake_combo_prediction.json
