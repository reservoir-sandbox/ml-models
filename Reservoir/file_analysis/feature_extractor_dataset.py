#!/usr/bin/env python3
"""
Reservoir ML MVP Feature Extractor

Purpose:
- Analyze Linux ELF binaries.
- Extract raw evidence useful for reports.
- Extract flat ML-ready features.
- Build a labeled dataset CSV from clean/suspicious folders.

Commands:
1) Analyze one ELF:
   python feature_extractor_dataset.py analyze --input samples/clean/bat --output output/bat_features.json

2) Build dataset:
   python feature_extractor_dataset.py build-dataset \
       --clean-dir samples/clean \
       --suspicious-dir samples/suspicious \
       --output-csv data/features.csv \
       --output-jsonl data/features.jsonl

Labels:
- clean files -> label 0
- suspicious files -> label 1

This script does NOT execute binaries. It only reads bytes and parses ELF structure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import lief
except ImportError:
    print("Missing dependency: lief. Install with: pip install lief", file=sys.stderr)
    raise


SUSPICIOUS_STRING_PATTERNS: dict[str, str] = {
    "has_str_bin_sh": r"/bin/sh",
    "has_str_bin_bash": r"/bin/bash",
    "has_str_wget": r"\bwget\b",
    "has_str_curl": r"\bcurl\b",
    "has_str_chmod": r"\bchmod\b",
    "has_str_chown": r"\bchown\b",
    "has_str_busybox": r"\bbusybox\b",
    "has_str_telnet": r"\btelnet\b",
    "has_str_netcat": r"\b(nc|netcat)\b",
    "has_str_etc_passwd": r"/etc/passwd",
    "has_str_etc_shadow": r"/etc/shadow",
    "has_str_ld_preload": r"ld_preload",
    "has_str_cron": r"cron",
    "has_str_iptables": r"iptables",
    "has_str_ssh": r"\bssh\b",
    "has_str_base64": r"base64",
    "has_str_tmp_path": r"/tmp/",
    "has_str_dev_shm": r"/dev/shm",
    "has_str_proc": r"/proc/",
    "has_str_http": r"http://",
    "has_str_https": r"https://",
}

SUSPICIOUS_IMPORTS: list[str] = [
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "gethostbyname", "getaddrinfo",
    "system", "execve", "execv", "execvp", "fork", "vfork", "clone",
    "popen", "kill",
    "open", "openat", "creat", "unlink", "remove", "rename", "chmod",
    "chown", "mkdir", "rmdir",
    "mmap", "mprotect", "munmap", "dlopen", "dlsym",
    "ptrace", "setuid", "setgid", "seteuid", "setegid", "chroot",
]

IMPORT_CATEGORIES: dict[str, set[str]] = {
    "network": {
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "gethostbyname", "getaddrinfo",
    },
    "process": {
        "system", "execve", "execv", "execvp", "fork", "vfork", "clone",
        "popen", "kill", "wait", "waitpid",
    },
    "filesystem": {
        "open", "openat", "creat", "unlink", "remove", "rename", "chmod",
        "chown", "mkdir", "rmdir", "read", "write",
    },
    "memory": {
        "mmap", "mprotect", "munmap", "dlopen", "dlsym", "malloc", "free",
    },
    "antidebug": {"ptrace"},
    "privilege": {
        "setuid", "setgid", "seteuid", "setegid", "chroot", "getuid", "geteuid",
    },
}

WEIRD_SECTION_KEYWORDS = ["upx", "packed", "crypt", "stub", "payload", "mal", "virus", "hack"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    value = 0.0
    for count in counts.values():
        p = count / total
        value -= p * math.log2(p)
    return round(value, 6)


def extract_ascii_strings(raw: bytes, min_len: int = 4, max_keep: int = 5000) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    for b in raw:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
                if len(result) >= max_keep:
                    return result
            current = []
    if len(current) >= min_len and len(result) < max_keep:
        result.append("".join(current))
    return result


def is_elf(raw: bytes) -> bool:
    return raw.startswith(b"\x7fELF")


def normalize_import_name(name: str) -> str:
    return name.split("@", 1)[0].strip()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def has_flag(obj: Any, flag_text: str) -> bool:
    try:
        return flag_text.upper() in str(obj.flags).upper()
    except Exception:
        return False


def parse_elf(path: Path, keep_raw: bool = False) -> dict[str, Any]:
    raw = path.read_bytes()
    features: dict[str, Any] = {
        "path": str(path),
        "filename": path.name,
        "sha256": sha256_file(path),
        "file_size": path.stat().st_size,
        "is_elf": int(is_elf(raw)),
        "parse_failed": 0,
        "label": None,
    }
    raw_evidence: dict[str, Any] = {"strings": [], "imports": {}, "sections": [], "segments": [], "metadata": {}}

    if not is_elf(raw):
        features["parse_failed"] = 1
        return {"features": features, "raw": raw_evidence}

    features["global_entropy"] = entropy(raw)

    try:
        binary = lief.parse(str(path))
    except Exception:
        binary = None

    if binary is None:
        features["parse_failed"] = 1
        return {"features": features, "raw": raw_evidence}

    try:
        features["entry_point"] = safe_int(binary.entrypoint)
    except Exception:
        features["entry_point"] = 0

    for attr, out_name in [
        ("sections", "num_sections"),
        ("segments", "num_segments"),
        ("symbols", "num_symbols"),
        ("dynamic_symbols", "num_dynamic_symbols"),
    ]:
        try:
            features[out_name] = len(getattr(binary, attr))
        except Exception:
            features[out_name] = 0

    header_lower = ""
    try:
        header_lower = str(binary.header).lower()
    except Exception:
        pass
    features["arch_x86_64"] = int("x86_64" in header_lower or "amd64" in header_lower)
    features["arch_x86"] = int(("i386" in header_lower or "80386" in header_lower) and not features["arch_x86_64"])
    features["arch_arm"] = int("arm" in header_lower)
    features["arch_aarch64"] = int("aarch64" in header_lower)

    section_entropies: list[float] = []
    executable_sections = 0
    writable_sections = 0
    zero_size_sections = 0
    weird_section_names = 0
    section_names: list[str] = []

    try:
        for section in binary.sections:
            name = section.name or ""
            section_names.append(name)
            content = bytes(section.content)
            ent = entropy(content)
            section_entropies.append(ent)
            is_exec = has_flag(section, "EXEC")
            is_write = has_flag(section, "WRITE")
            executable_sections += int(is_exec)
            writable_sections += int(is_write)
            zero_size_sections += int(safe_int(section.size) == 0)
            weird_section_names += int(any(k in name.lower() for k in WEIRD_SECTION_KEYWORDS))
            if keep_raw:
                raw_evidence["sections"].append({
                    "name": name,
                    "size": safe_int(section.size),
                    "entropy": ent,
                    "flags": str(section.flags),
                })
    except Exception:
        pass

    features["executable_sections"] = executable_sections
    features["writable_sections"] = writable_sections
    features["zero_size_sections"] = zero_size_sections
    features["weird_section_names"] = weird_section_names
    features["mean_section_entropy"] = round(sum(section_entropies) / len(section_entropies), 6) if section_entropies else 0.0
    features["max_section_entropy"] = max(section_entropies) if section_entropies else 0.0
    features["min_section_entropy"] = min(section_entropies) if section_entropies else 0.0

    for sec in ["text", "data", "rodata", "bss", "symtab", "strtab", "dynsym", "dynamic", "interp"]:
        features[f"has_section_{sec}"] = int(f".{sec}" in section_names)
    features["has_section_upx"] = int(any("upx" in s.lower() for s in section_names))

    has_rwx_segment = 0
    has_exec_stack = 0
    try:
        for segment in binary.segments:
            r = has_flag(segment, "R")
            w = has_flag(segment, "W")
            x = has_flag(segment, "X")
            has_rwx_segment = max(has_rwx_segment, int(r and w and x))
            if "GNU_STACK" in str(segment.type).upper() and x:
                has_exec_stack = 1
            if keep_raw:
                raw_evidence["segments"].append({
                    "type": str(segment.type),
                    "flags": str(segment.flags),
                    "physical_size": safe_int(segment.physical_size),
                    "virtual_size": safe_int(segment.virtual_size),
                })
    except Exception:
        pass
    features["has_rwx_segment"] = has_rwx_segment
    features["has_exec_stack"] = has_exec_stack

    imported_names: set[str] = set()
    try:
        for sym in binary.imported_symbols:
            if sym.name:
                imported_names.add(normalize_import_name(sym.name))
    except Exception:
        pass

    category_to_imports: dict[str, list[str]] = {k: [] for k in IMPORT_CATEGORIES}
    category_to_imports["other"] = []
    for name in sorted(imported_names):
        placed = False
        for category, names in IMPORT_CATEGORIES.items():
            if name in names:
                category_to_imports[category].append(name)
                placed = True
        if not placed:
            category_to_imports["other"].append(name)

    for category, names in category_to_imports.items():
        features[f"num_{category}_imports"] = len(names)
    for imp in SUSPICIOUS_IMPORTS:
        features[f"has_import_{imp}"] = int(imp in imported_names)
    if keep_raw:
        raw_evidence["imports"] = category_to_imports

    strings = extract_ascii_strings(raw)
    lower_strings = [s.lower() for s in strings]
    features["num_strings"] = len(strings)
    features["avg_string_len"] = round(sum(len(s) for s in strings) / len(strings), 6) if strings else 0.0
    features["max_string_len"] = max((len(s) for s in strings), default=0)

    for feature_name, pattern in SUSPICIOUS_STRING_PATTERNS.items():
        regex = re.compile(pattern, flags=re.IGNORECASE)
        features[feature_name] = int(any(regex.search(s) for s in lower_strings))

    features["num_url_strings"] = sum(1 for s in lower_strings if "http://" in s or "https://" in s)
    features["num_ip_like_strings"] = sum(1 for s in lower_strings if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s))
    features["num_path_like_strings"] = sum(1 for s in lower_strings if "/" in s)
    features["num_shell_like_strings"] = sum(1 for s in lower_strings if any(x in s for x in ["/bin/sh", "/bin/bash", "sh -c", "bash -c"]))

    if keep_raw:
        raw_evidence["strings"] = [{"value": s} for s in strings[:1000]]

    features["has_upx"] = features["has_section_upx"]
    features["is_stripped"] = int(features["has_section_symtab"] == 0)
    features["is_static"] = int(features["has_section_interp"] == 0 and len(imported_names) == 0)

    heuristic_score = 0.0
    heuristic_score += 0.20 if features["global_entropy"] > 7.0 else 0.0
    heuristic_score += 0.15 if features["max_section_entropy"] > 7.2 else 0.0
    heuristic_score += 0.15 if features["has_rwx_segment"] else 0.0
    heuristic_score += 0.15 if features["has_exec_stack"] else 0.0
    heuristic_score += min(features["num_network_imports"] * 0.04, 0.16)
    heuristic_score += min(features["num_process_imports"] * 0.035, 0.14)
    suspicious_string_count = sum(features[name] for name in SUSPICIOUS_STRING_PATTERNS.keys())
    heuristic_score += min(suspicious_string_count * 0.04, 0.20)
    features["heuristic_score"] = round(min(heuristic_score, 1.0), 6)

    raw_evidence["metadata"] = {
        "is_stripped": bool(features["is_stripped"]),
        "is_static": bool(features["is_static"]),
        "has_upx": bool(features["has_upx"]),
        "has_rwx_segment": bool(features["has_rwx_segment"]),
        "has_exec_stack": bool(features["has_exec_stack"]),
        "section_names": section_names,
    }
    return {"features": features, "raw": raw_evidence}


def iter_candidate_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    result: list[Path] = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".c", ".cpp", ".h", ".hpp", ".json", ".jsonl", ".csv", ".md", ".txt"}:
            continue
        result.append(path)
    return sorted(result)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("No rows to write")
    priority = ["label", "path", "filename", "sha256", "file_size", "is_elf", "parse_failed"]
    all_keys = set()
    for row in rows:
        all_keys.update(row.keys())
    fieldnames = [k for k in priority if k in all_keys]
    fieldnames += sorted(k for k in all_keys if k not in set(fieldnames))
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def analyze_one(args: argparse.Namespace) -> None:
    result = parse_elf(Path(args.input), keep_raw=args.keep_raw)
    output = {"features": result["features"], "raw": result["raw"]}
    if args.output:
        write_json(Path(args.output), output)
        print(f"Saved analysis to {args.output}")
    else:
        print(json.dumps(output, indent=2, ensure_ascii=False))


def build_dataset(args: argparse.Namespace) -> None:
    rows: list[dict[str, Any]] = []
    jsonl_records: list[dict[str, Any]] = []
    for directory, label in [(Path(args.clean_dir), 0), (Path(args.suspicious_dir), 1)]:
        files = iter_candidate_files(directory)
        print(f"Found {len(files)} candidate files in {directory} with label={label}")
        for path in files:
            try:
                result = parse_elf(path, keep_raw=args.keep_raw)
                features = result["features"]
                features["label"] = label
                if not args.include_non_elf and features.get("is_elf", 0) != 1:
                    continue
                rows.append(features)
                jsonl_records.append({"features": features, "raw": result["raw"] if args.keep_raw else {}})
            except Exception as exc:
                print(f"[WARN] failed to process {path}: {exc}", file=sys.stderr)
    if not rows:
        raise RuntimeError("No rows produced. Check input folders and ELF files.")
    write_csv(Path(args.output_csv), rows)
    if args.output_jsonl:
        out_jsonl = Path(args.output_jsonl)
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with out_jsonl.open("w", encoding="utf-8") as f:
            for record in jsonl_records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"Saved CSV dataset to {args.output_csv}")
    if args.output_jsonl:
        print(f"Saved JSONL records to {args.output_jsonl}")
    print("Dataset summary:")
    print(f"  total: {len(rows)}")
    print(f"  clean: {sum(1 for r in rows if r['label'] == 0)}")
    print(f"  suspicious: {sum(1 for r in rows if r['label'] == 1)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reservoir ELF feature extractor and dataset builder")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze", help="Analyze one ELF binary")
    analyze_parser.add_argument("--input", required=True, help="Path to ELF binary")
    analyze_parser.add_argument("--output", help="Path to output JSON")
    analyze_parser.add_argument("--keep-raw", action="store_true", help="Keep raw strings/imports/sections in output")
    analyze_parser.set_defaults(func=analyze_one)
    build_parser = subparsers.add_parser("build-dataset", help="Build labeled feature dataset")
    build_parser.add_argument("--clean-dir", required=True, help="Directory with clean/benign ELF files")
    build_parser.add_argument("--suspicious-dir", required=True, help="Directory with suspicious/malicious ELF files")
    build_parser.add_argument("--output-csv", required=True, help="Output features CSV")
    build_parser.add_argument("--output-jsonl", help="Optional output JSONL with features and raw evidence")
    build_parser.add_argument("--keep-raw", action="store_true", help="Keep raw evidence in JSONL")
    build_parser.add_argument("--include-non-elf", action="store_true", help="Include non-ELF files instead of skipping")
    build_parser.set_defaults(func=build_dataset)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
