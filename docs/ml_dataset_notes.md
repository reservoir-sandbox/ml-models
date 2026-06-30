# ML Dataset Notes

Current MVP dataset:

- clean Linux ELF samples generated from harmless C programs
- synthetic suspicious Linux ELF samples generated from harmless C programs
- suspicious samples contain static indicators only and do not perform harmful behavior

Why no real malware download is included:

- public malware sources may contain live malware
- handling real malware requires an isolated workflow, storage policy, and team approval
- many large public ML malware datasets are Windows PE-focused rather than Linux ELF-focused

Safe next steps:

1. Add more benign Linux ELF binaries from trusted Ubuntu packages.
2. Add more harmless synthetic ELF variants to improve feature coverage.
3. If the team obtains a safe labeled feature CSV, pass it to training with:

```bash
python3 -m Reservoir.file_analysis.train_baseline_model \
  --input-csv data/features.csv \
  --extra-csv path/to/external_features.csv
```

4. Only handle real malware inside the sandbox/orchestrator workflow after safety rules are defined.
