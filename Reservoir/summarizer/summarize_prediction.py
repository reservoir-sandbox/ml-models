#!/usr/bin/env python3
"""Generate a concise Reservoir analysis summary from a prediction JSON file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STRING_LABELS = {
    "base64": "base64",
    "bin_bash": "/bin/bash",
    "bin_sh": "/bin/sh",
    "busybox": "busybox",
    "chmod": "chmod",
    "chown": "chown",
    "cron": "cron",
    "curl": "curl",
    "dev_shm": "/dev/shm",
    "etc_passwd": "/etc/passwd",
    "etc_shadow": "/etc/shadow",
    "http": "http://",
    "https": "https://",
    "iptables": "iptables",
    "ld_preload": "LD_PRELOAD",
    "netcat": "netcat/nc",
    "proc": "/proc",
    "ssh": "ssh",
    "telnet": "telnet",
    "tmp_path": "/tmp",
    "wget": "wget",
}

IMPORT_GROUPS = {
    "network": {"socket", "connect", "bind", "listen", "accept", "send", "recv", "getaddrinfo", "gethostbyname"},
    "process": {"system", "execve", "execv", "execvp", "fork", "popen", "kill"},
    "memory": {"mmap", "mprotect", "munmap", "dlopen", "dlsym"},
    "privilege": {"setuid", "setgid", "seteuid", "setegid", "chroot", "ptrace"},
}


def as_percent(value: Any) -> str:
    if value is None:
        return "unknown"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "unknown"


def risk_level(predicted_class: str, probability: Any, heuristic_score: Any) -> str:
    try:
        probability_value = float(probability or 0.0)
    except (TypeError, ValueError):
        probability_value = 0.0
    try:
        heuristic_value = float(heuristic_score or 0.0)
    except (TypeError, ValueError):
        heuristic_value = 0.0

    if predicted_class != "suspicious":
        return "Low"
    if probability_value >= 0.85 or heuristic_value >= 0.5:
        return "High"
    if probability_value >= 0.6 or heuristic_value >= 0.25:
        return "Medium"
    return "Low"


def display_strings(values: list[str], limit: int = 12) -> str:
    labels = [STRING_LABELS.get(value, value.replace("_", " ")) for value in values]
    if not labels:
        return "none detected"
    shown = labels[:limit]
    suffix = f" and {len(labels) - limit} more" if len(labels) > limit else ""
    return ", ".join(shown) + suffix


def group_imports(imports: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {name: [] for name in IMPORT_GROUPS}
    grouped["other"] = []
    for imported in imports:
        placed = False
        for group, names in IMPORT_GROUPS.items():
            if imported in names:
                grouped[group].append(imported)
                placed = True
        if not placed:
            grouped["other"].append(imported)
    return {group: sorted(values) for group, values in grouped.items() if values}


def bullet_list(values: list[str]) -> str:
    if not values:
        return "- None detected"
    return "\n".join(f"- {value}" for value in values)


def build_summary(prediction: dict[str, Any]) -> str:
    features = prediction.get("features", {})
    evidence = prediction.get("evidence", {})
    evidence_strings = list(evidence.get("strings", []))
    evidence_imports = list(evidence.get("imports", []))

    filename = features.get("filename") or Path(str(prediction.get("input", "unknown"))).name
    sha256 = prediction.get("sha256") or features.get("sha256") or "unknown"
    predicted_class = str(prediction.get("predicted_class", "unknown"))
    probability = prediction.get("suspicious_probability")
    heuristic_score = prediction.get("heuristic_score")
    risk = risk_level(predicted_class, probability, heuristic_score)
    grouped_imports = group_imports(evidence_imports)

    string_sentence = display_strings(evidence_strings)
    import_sentence = ", ".join(f"{group}: {', '.join(values)}" for group, values in grouped_imports.items())
    if not import_sentence:
        import_sentence = "none detected"

    lines = [
        "# Reservoir File Analysis Summary",
        "",
        f"File: `{filename}`",
        f"SHA-256: `{sha256}`",
        f"Verdict: **{predicted_class.upper()}**",
        f"Suspicious probability: **{as_percent(probability)}**",
        f"Risk level: **{risk}**",
        "",
        "## Executive Summary",
        "",
        (
            f"Reservoir classified `{filename}` as **{predicted_class}** based on static ELF analysis. "
            f"The strongest static indicators include {string_sentence}. "
            f"Imported API evidence includes {import_sentence}."
        ),
        "",
        "This analysis is static only: the binary was not executed.",
        "",
        "## Key Evidence",
        "",
        "Suspicious strings:",
        bullet_list([STRING_LABELS.get(value, value.replace("_", " ")) for value in evidence_strings]),
        "",
        "Suspicious imports:",
        bullet_list(evidence_imports),
        "",
        "## Technical Snapshot",
        "",
        f"- File size: {features.get('file_size', 'unknown')} bytes",
        f"- ELF detected: {bool(prediction.get('is_elf', features.get('is_elf', False)))}",
        f"- Sections: {features.get('num_sections', 'unknown')}",
        f"- Segments: {features.get('num_segments', 'unknown')}",
        f"- Strings extracted: {features.get('num_strings', 'unknown')}",
        f"- Network imports: {features.get('num_network_imports', 'unknown')}",
        f"- Process imports: {features.get('num_process_imports', 'unknown')}",
        f"- Memory imports: {features.get('num_memory_imports', 'unknown')}",
        f"- Heuristic score: {heuristic_score}",
        "",
        "## Notes",
        "",
        (
            "This MVP summary is generated from structured static-analysis output. "
            "It is intended for quick analyst review and future integration with the Reservoir report UI. "
            "The current model was trained on a small synthetic dataset, so the result should not be treated as production malware detection."
        ),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a Reservoir prediction JSON into Markdown")
    parser.add_argument("--input", required=True, help="Prediction JSON from Reservoir/file_analysis/predict_file.py")
    parser.add_argument("--output", help="Output Markdown path. If omitted, prints to stdout.")
    args = parser.parse_args()

    prediction = json.loads(Path(args.input).read_text(encoding="utf-8"))
    summary = build_summary(prediction)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary, encoding="utf-8")
        print(f"Saved summary to {output_path}")
    else:
        print(summary)


if __name__ == "__main__":
    main()
