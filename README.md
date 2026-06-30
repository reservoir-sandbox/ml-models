# Reservoir ML

Reservoir is an automated Linux malware-analysis sandbox. This folder contains the ML-side MVP work.

Current ML areas:

- `Reservoir/file_analysis`: static ELF feature extraction, dataset generation, baseline classification.
- `Reservoir/summarizer`: prediction JSON to analyst-style Markdown summary.
- `Reservoir/api`: Flask API for upload-based analysis and summary generation.

The first working MVP path is:

```text
safe ELF samples -> static features -> features.csv -> baseline model -> prediction JSON
```

Run the full file-analysis MVP in Docker. This helper stages the project under
`/private/tmp` first, which avoids Docker Desktop file-sharing problems when the
repo lives outside `/Users`.

```bash
bash scripts/run_ml_mvp_in_docker.sh
```

The command creates Linux ELF samples, builds `data/features.csv`, trains `models/file_analysis_baseline.joblib`, and writes `output/fake_combo_prediction.json`.

If the files already exist and you only want to test the trained model:

```bash
bash scripts/test_file_analysis_model_in_docker.sh
```

To predict one ELF file:

```bash
bash scripts/predict_file_in_docker.sh samples/suspicious/fake_combo
```

To generate a readable Markdown summary from a prediction:

```bash
bash scripts/summarize_prediction.sh output/fake_combo_prediction.json
```

To run the ML HTTP API:

```bash
bash scripts/run_ml_api_in_docker.sh
```

Useful API test:

```bash
bash scripts/test_ml_api_in_docker.sh
```
