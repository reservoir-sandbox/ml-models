# Reservoir ML MVP Feature Extractor

Update: the canonical implementation now lives in
`Reservoir/file_analysis/feature_extractor_dataset.py`. The old
`mvp analysis/feature_extractor_dataset.py` path is kept as a compatibility
wrapper.

This folder contains a stronger ELF feature extractor for the malware-analysis MVP.

It does two things:

1. Analyze one ELF binary and output JSON.
2. Build a labeled ML dataset from two folders:
   - clean binaries -> label `0`
   - suspicious binaries -> label `1`

## Install

Use Linux or Docker. macOS system binaries are usually Mach-O, not ELF.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install lief
```

If you are on macOS, run inside Ubuntu Docker:

```bash
docker run -it --rm -v "$PWD":/work ubuntu:22.04 bash
apt update
apt install -y python3 python3-pip
pip3 install lief
cd /work
```

## Analyze one file

```bash
python3 feature_extractor_dataset.py analyze \
  --input samples/clean/bat \
  --output output/bat_analysis.json \
  --keep-raw
```

Without raw strings/sections:

```bash
python3 feature_extractor_dataset.py analyze \
  --input samples/clean/bat \
  --output output/bat_features.json
```

## Build dataset

Expected folder structure:

```text
samples/
  clean/
    bat
    busybox_x86_64
  suspicious/
    fake_downloader
    fake_reverse_shell_strings
data/
```

Run:

```bash
python3 feature_extractor_dataset.py build-dataset \
  --clean-dir samples/clean \
  --suspicious-dir samples/suspicious \
  --output-csv data/features.csv \
  --output-jsonl data/features.jsonl
```

With raw evidence in JSONL:

```bash
python3 feature_extractor_dataset.py build-dataset \
  --clean-dir samples/clean \
  --suspicious-dir samples/suspicious \
  --output-csv data/features.csv \
  --output-jsonl data/features.jsonl \
  --keep-raw
```

## Output

The CSV is ML-ready. Each row is one ELF file.

Important columns:

```text
label
file_size
global_entropy
num_sections
num_segments
num_strings
num_network_imports
num_process_imports
num_filesystem_imports
num_memory_imports
has_import_socket
has_import_execve
has_import_ptrace
has_str_wget
has_str_curl
has_str_bin_sh
has_str_etc_passwd
has_rwx_segment
has_exec_stack
is_static
is_stripped
heuristic_score
```

## Next ML step

Train a baseline:

```text
features.csv -> RandomForestClassifier / LogisticRegression
```

For MVP, use synthetic suspicious ELF files. In the report, clearly call them synthetic.
