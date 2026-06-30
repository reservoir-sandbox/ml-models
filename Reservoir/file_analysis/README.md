# Reservoir File Analysis MVP

This package contains the first ML MVP for Reservoir's static Linux ELF analysis.

It currently supports:

1. Static ELF feature extraction with `feature_extractor_dataset.py`.
2. Dataset generation from `samples/clean` and `samples/suspicious`.
3. Model training with candidate model selection in `train_baseline_model.py`.
4. Single-file prediction with `predict_file.py`.

## Build Everything In Docker

From the repository root on macOS/Docker Desktop:

```bash
bash scripts/run_ml_mvp_in_docker.sh
```

The helper stages the project under `/private/tmp` first, then copies the
generated artifacts back. This avoids Docker Desktop file-sharing problems when
the repo is under `/Applications`.

If your repo is already in a Docker-shared path, you can also run:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/work \
  -w /work \
  ubuntu:22.04 \
  bash scripts/run_ml_mvp_inside_container.sh
```

Outputs:

```text
samples/clean/
samples/suspicious/
data/features.csv
data/features.jsonl
data/file_analysis_model_metrics.json
data/file_analysis_feature_importance.csv
models/file_analysis_baseline.joblib
models/file_analysis_feature_columns.json
output/fake_combo_prediction.json
```

## Run Locally On Ubuntu

```bash
python3 -m pip install -r requirements.txt
bash scripts/build_clean_samples.sh
bash build_suspicious_samples.sh

python3 -m Reservoir.file_analysis.feature_extractor_dataset build-dataset \
  --clean-dir samples/clean \
  --suspicious-dir samples/suspicious \
  --output-csv data/features.csv \
  --output-jsonl data/features.jsonl \
  --keep-raw

python3 -m Reservoir.file_analysis.train_baseline_model
```

## Predict One File

On macOS/Docker Desktop, use the helper:

```bash
bash scripts/predict_file_in_docker.sh samples/suspicious/fake_combo
```

It writes:

```text
output/fake_combo_prediction.json
```

On Ubuntu, or any environment with `requirements.txt` installed, you can run
the Python module directly:

```bash
python3 -m Reservoir.file_analysis.predict_file \
  --input samples/suspicious/fake_combo \
  --output output/fake_combo_prediction.json
```

## Test The Existing Model

If the model and sample files already exist, run:

```bash
bash scripts/test_file_analysis_model_in_docker.sh
```

Outputs:

```text
output/model_test_predictions.csv
output/model_test_summary.json
```

## External Feature CSV

If a safe labeled external feature CSV is available with the same schema, it can
be merged during training:

```bash
python3 -m Reservoir.file_analysis.train_baseline_model \
  --input-csv data/features.csv \
  --extra-csv path/to/external_features.csv
```

Important: the suspicious class is synthetic and harmless. This MVP proves the pipeline shape; it is not a real-world malware detector yet.
