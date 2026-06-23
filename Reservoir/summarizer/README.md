# Reservoir Summarizer

This module contains the first MVP for summarizing Reservoir file-analysis
results.

The current implementation is a deterministic summarizer: it takes prediction
JSON from `Reservoir/file_analysis/predict_file.py` and turns it into a concise
Markdown analysis report. It does not require an LLM, network access, or model
deployment.

## Run

```bash
bash scripts/summarize_prediction.sh output/fake_combo_prediction.json
```

Or directly:

```bash
python3 -m Reservoir.summarizer.summarize_prediction \
  --input output/fake_combo_prediction.json \
  --output output/fake_combo_summary.md
```

## Input

Prediction JSON containing:

- predicted class
- suspicious probability
- heuristic score
- suspicious strings/imports
- extracted static features

## Output

A Markdown report with:

- verdict
- risk level
- executive summary
- key evidence
- technical snapshot
- limitations/notes

## Future Options

The deterministic MVP can later be upgraded in several ways:

1. Local LLM summarization, for example a Llama-family model through Ollama or
   vLLM.
2. Hosted LLM summarization through an API.
3. Hybrid mode, where this deterministic summary provides the evidence and an
   LLM rewrites it into a more natural analyst report.
