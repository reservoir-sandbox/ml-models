#!/usr/bin/env python3
"""K8s Job entrypoint: forward the static-analysis report to the external LLM
summarizer (see LLM_integration.md in gitops-deployment), then relay its
response back to the backend callback API.

Runs after the static task completes - the backend only launches this task
once it has a static report to hand over (either inline via STATIC_REPORT or
as an S3 pointer via STATIC_REPORT_S3_KEY). It never touches the raw sample.

Env var contract otherwise mirrors the reverse/auto-yara workers so all three
analysis workers are launched identically by charts/job-to-run.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import aioboto3
import aiohttp

INLINE_RESULT_THRESHOLD_BYTES = 1024 * 1024


def get_iso_time() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def load_static_report(session, endpoint_url, access_key, secret_key, bucket_name, s3_key, task_id, raw_inline):
    if s3_key:
        temp_file = Path(f"/tmp/{task_id}_static_report.json")
        try:
            async with session.client(
                "s3", endpoint_url=endpoint_url, aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="local-cluster"
            ) as s3:
                await s3.download_file(Bucket=bucket_name, Key=s3_key, Filename=str(temp_file))
            return json.loads(temp_file.read_text(encoding="utf-8"))
        finally:
            if temp_file.exists():
                temp_file.unlink()

    if raw_inline:
        parsed = json.loads(raw_inline)
        if isinstance(parsed, dict):
            return parsed

    raise RuntimeError("No static analysis report available (neither STATIC_REPORT nor STATIC_REPORT_S3_KEY set)")


async def send_error_callback(url: str, headers: dict, error_msg: str, started_at: str):
    finished_at = get_iso_time()
    error_payload = {
        "status": "failed",
        "error": error_msg,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            await http_session.post(url, headers=headers, json=error_payload)
    except Exception as network_err:
        print(f"Failed to deliver error callback: {network_err}")


async def main():
    started_at = get_iso_time()

    ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
    SECRET_KEY = os.getenv("S3_SECRET_KEY")
    ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL")
    BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

    BACKEND_CALLBACK_URL = os.getenv("BACKEND_CALLBACK_URL")
    WORKER_CALLBACK_SECRET = os.getenv("WORKER_CALLBACK_SECRET")
    TASK_ID = os.getenv("TASK_ID")
    SHA256 = os.getenv("SHA256")

    SUMMARIZER_URL = os.getenv("RESERVOIR_SUMMARIZER_URL")
    SUMMARIZER_TIMEOUT_SECONDS = float(os.getenv("RESERVOIR_SUMMARIZER_TIMEOUT_SECONDS", "300"))
    STATIC_REPORT_RAW = os.getenv("STATIC_REPORT", "")
    STATIC_REPORT_S3_KEY = os.getenv("STATIC_REPORT_S3_KEY", "")

    if not all([ACCESS_KEY, SECRET_KEY, ENDPOINT_URL, BUCKET_NAME, BACKEND_CALLBACK_URL, WORKER_CALLBACK_SECRET, TASK_ID, SUMMARIZER_URL]):
        print(json.dumps({"error": "Critical configuration missing from environment variables."}))
        sys.exit(1)

    if not BACKEND_CALLBACK_URL.endswith("/callback"):
        callback_url = f"{BACKEND_CALLBACK_URL.rstrip('/')}/api/v1/internal/tasks/{TASK_ID}/callback"
    else:
        callback_url = BACKEND_CALLBACK_URL

    http_headers = {
        "X-Worker-Token": WORKER_CALLBACK_SECRET,
        "Content-Type": "application/json",
    }

    session = aioboto3.Session()

    try:
        static_report = await load_static_report(
            session, ENDPOINT_URL, ACCESS_KEY, SECRET_KEY, BUCKET_NAME, STATIC_REPORT_S3_KEY, TASK_ID, STATIC_REPORT_RAW
        )

        summarize_payload = {
            "task_id": str(TASK_ID),
            "status": "success",
            "location": "inline",
            "report": static_report,
            "sha256": SHA256,
        }

        summarizer_timeout = aiohttp.ClientTimeout(total=SUMMARIZER_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=summarizer_timeout) as http_session:
            async with http_session.post(
                f"{SUMMARIZER_URL.rstrip('/')}/api/v1/summarize-static",
                headers={"Content-Type": "application/json"},
                json=summarize_payload,
            ) as response:
                if response.status != 200:
                    body = await response.text()
                    raise RuntimeError(f"Summarizer returned HTTP {response.status}: {body[:500]}")
                report = await response.json()

        json_string = json.dumps(report)
        payload_bytes = json_string.encode("utf-8")
        finished_at = get_iso_time()

        callback_payload = {
            "status": "completed",
            "started_at": started_at,
            "finished_at": finished_at,
        }

        if len(payload_bytes) <= INLINE_RESULT_THRESHOLD_BYTES:
            callback_payload["result"] = report
        else:
            output_report_key = f"reports/{TASK_ID}_report.json"
            async with session.client(
                "s3", endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name="local-cluster"
            ) as s3:
                await s3.put_object(
                    Bucket=BUCKET_NAME, Key=output_report_key, Body=payload_bytes, ContentType="application/json"
                )
            callback_payload["report_object_name"] = output_report_key

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.post(callback_url, headers=http_headers, json=callback_payload) as response:
                if response.status not in [200, 201, 202, 204]:
                    print(f"Failed to post success callback. HTTP Status: {response.status}")
                    body = await response.text()
                    print(f"Backend response: {body}")

    except asyncio.TimeoutError:
        error_msg = "Summarizer request timed out."
        print(error_msg)
        await send_error_callback(callback_url, http_headers, error_msg, started_at)
    except Exception as err:
        print(f"Execution Error: {err}")
        await send_error_callback(callback_url, http_headers, str(err), started_at)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
