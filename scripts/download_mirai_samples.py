#!/usr/bin/env python3
"""
download_mirai_samples.py

Downloads Mirai-family ELF malware samples from MalwareBazaar (abuse.ch)
for use in offline/static ML-detection research (no dynamic analysis).

Usage:
    export MB_API_KEY="your-api-key-here"
    python3 download_mirai_samples.py --tag Mirai --limit 1000 --outdir ./mirai_samples

MalwareBazaar API docs: https://bazaar.abuse.ch/api/

Notes:
- Samples are served as password-protected ZIPs; password is always "infected".
- Please be respectful of abuse.ch's infrastructure: this script paces requests
  and caches metadata/progress so you can resume instead of re-querying everything.
- Downloaded files are LIVE MALWARE. Handle only inside an isolated environment,
  keep them encrypted at rest if stored beyond the sandbox, and never execute them.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from datetime import datetime, timezone

import requests

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
REQUEST_DELAY_SEC = 1.5  # be polite to the API


def get_api_key():
    key = os.environ.get("MB_API_KEY")
    if not key:
        sys.exit(
            "ERROR: Set your MalwareBazaar API key in the MB_API_KEY environment "
            "variable, e.g.:\n  export MB_API_KEY='your-key-here'"
        )
    return key


def query_tag(session, tag, limit):
    """
    Query MalwareBazaar for samples with a given tag.
    Returns a list of sample metadata dicts.
    """
    data = {"query": "get_taginfo", "tag": tag, "limit": str(limit)}
    resp = session.post(API_URL, data=data, timeout=30)
    resp.raise_for_status()
    payload = resp.json()

    if payload.get("query_status") != "ok":
        sys.exit(f"ERROR querying tag '{tag}': {payload.get('query_status')}")

    return payload.get("data", [])


def download_sample(session, sha256_hash, outdir, keep_zip=False):
    """
    Downloads a single sample by sha256 hash, unzips it (password: infected),
    and writes both the raw binary and a metadata sidecar.
    Returns True on success, False on failure.
    """
    data = {"query": "get_file", "sha256_hash": sha256_hash}
    resp = session.post(API_URL, data=data, timeout=60)

    if resp.status_code != 200 or resp.headers.get("Content-Type") != "application/zip":
        # API returned JSON error instead of a zip
        try:
            err = resp.json()
        except Exception:
            err = resp.text[:200]
        print(f"  [!] download failed for {sha256_hash}: {err}")
        return False

    zip_bytes = resp.content

    if keep_zip:
        zip_path = os.path.join(outdir, "zips", f"{sha256_hash}.zip")
        os.makedirs(os.path.dirname(zip_path), exist_ok=True)
        with open(zip_path, "wb") as f:
            f.write(zip_bytes)

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            if not names:
                print(f"  [!] empty zip for {sha256_hash}")
                return False
            inner_name = names[0]
            raw = zf.read(inner_name, pwd=ZIP_PASSWORD)
    except RuntimeError as e:
        print(f"  [!] failed to unzip {sha256_hash} (bad password / corrupt?): {e}")
        return False
    except zipfile.BadZipFile:
        print(f"  [!] bad zip file for {sha256_hash}")
        return False

    # sanity check hash matches what we asked for
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != sha256_hash.lower():
        print(f"  [!] hash mismatch for {sha256_hash} (got {actual_sha256}), keeping anyway")

    samples_dir = os.path.join(outdir, "samples")
    os.makedirs(samples_dir, exist_ok=True)
    out_path = os.path.join(samples_dir, f"{sha256_hash}.elf")
    with open(out_path, "wb") as f:
        f.write(raw)

    return True


def load_progress(progress_path):
    if os.path.exists(progress_path):
        with open(progress_path, "r") as f:
            return set(json.load(f))
    return set()


def save_progress(progress_path, done_set):
    with open(progress_path, "w") as f:
        json.dump(sorted(done_set), f)


def main():
    ap = argparse.ArgumentParser(description="Download Mirai ELF samples from MalwareBazaar")
    ap.add_argument("--tag", default="Mirai", help="MalwareBazaar tag to query (default: Mirai)")
    ap.add_argument("--limit", type=int, default=1000, help="Max samples to fetch (default: 1000)")
    ap.add_argument("--outdir", default="./mirai_samples", help="Output directory")
    ap.add_argument("--keep-zip", action="store_true", help="Also keep the original encrypted zip")
    ap.add_argument(
        "--file-type",
        default="elf",
        help="Filter to this file_type as reported by MalwareBazaar (default: elf). "
             "Use 'any' to disable filtering.",
    )
    args = ap.parse_args()

    api_key = get_api_key()
    os.makedirs(args.outdir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"Auth-Key": api_key})

    print(f"[*] Querying MalwareBazaar for tag='{args.tag}' (requesting up to {args.limit})...")
    entries = query_tag(session, args.tag, args.limit)
    print(f"[*] Tag query returned {len(entries)} entries total")

    if args.file_type.lower() != "any":
        entries = [e for e in entries if str(e.get("file_type", "")).lower() == args.file_type.lower()]
        print(f"[*] After filtering to file_type='{args.file_type}': {len(entries)} entries")

    if len(entries) < args.limit:
        print(
            f"[!] Only {len(entries)} matching samples available from this query "
            f"(tag query max is limited by the API / how much abuse.ch has tagged/shared). "
            f"Consider combining tags (e.g. 'Mirai', 'mirai_variant') if you need more."
        )

    entries = entries[: args.limit]

    metadata_path = os.path.join(args.outdir, "metadata.csv")
    progress_path = os.path.join(args.outdir, "_progress.json")
    done = load_progress(progress_path)

    fieldnames = [
        "sha256_hash", "sha1_hash", "md5_hash", "file_name", "file_size",
        "file_type", "signature", "first_seen", "last_seen", "tags",
        "reporter", "delivery_method", "downloaded",
    ]
    write_header = not os.path.exists(metadata_path)
    meta_f = open(metadata_path, "a", newline="")
    writer = csv.DictWriter(meta_f, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()

    total = len(entries)
    ok_count = 0
    fail_count = 0
    skip_count = 0

    for i, entry in enumerate(entries, 1):
        sha256 = entry.get("sha256_hash")
        if not sha256:
            continue

        if sha256 in done:
            skip_count += 1
            continue

        print(f"[{i}/{total}] {sha256}  ({entry.get('file_name')}, {entry.get('file_size')} bytes)")

        success = download_sample(session, sha256, args.outdir, keep_zip=args.keep_zip)

        row = {k: entry.get(k, "") for k in fieldnames if k != "downloaded"}
        row["tags"] = ",".join(entry.get("tags") or [])
        row["downloaded"] = success
        writer.writerow(row)
        meta_f.flush()

        if success:
            ok_count += 1
            done.add(sha256)
            save_progress(progress_path, done)
        else:
            fail_count += 1

        time.sleep(REQUEST_DELAY_SEC)

    meta_f.close()

    print("\n[*] Done.")
    print(f"    Downloaded successfully: {ok_count}")
    print(f"    Failed:                  {fail_count}")
    print(f"    Skipped (already done):  {skip_count}")
    print(f"    Samples dir:             {os.path.join(args.outdir, 'samples')}")
    print(f"    Metadata CSV:            {metadata_path}")
    print(f"\n[!] Reminder: these are live malware binaries. Never execute them.")
    print(f"    Timestamp: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()