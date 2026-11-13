r"""Replay CSV feature rows against the local CICIoT23 Sentinel API.

Run from ``backend-fastapi``:
    python testSimulator.py --csv ..\ml\sample_data\test_sample_500.csv

The generated request body matches BatchPredictionRequest:
    {"data": [<flow>, ...]}
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import requests

API_URL = "http://localhost:8000/api/v1/predict/batch"
DEFAULT_CSV = Path(__file__).resolve().parents[1] / "ml" / "sample_data" / "test_sample_500.csv"
BATCH_SIZE = 10

BASE_18 = [
    "flow_duration", "Rate", "Header_Length", "Duration",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ack_count", "syn_count",
    "fin_count", "rst_count", "TCP", "UDP", "ICMP", "AVG", "Std",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay CICIoT23 CSV rows to FastAPI.")
    parser.add_argument("--url", default=API_URL, help="FastAPI batch endpoint.")
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="CSV file to replay.")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE, help="Rows per request.")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between requests.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum rows to replay.")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout.")
    parser.add_argument("--print-only", action="store_true", help="Print one request without sending it.")
    return parser.parse_args()


def require_headers(headers: list[str]) -> None:
    missing = [feature for feature in BASE_18 if feature not in headers]
    if missing:
        raise ValueError("CSV is missing required 18-feature columns: " + ", ".join(missing))


def flow_from_row(row: dict[str, str], row_number: int) -> dict[str, object]:
    try:
        features = {feature: float(row[feature]) for feature in BASE_18}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"row {row_number} contains an invalid feature value") from exc

    return {
        **features,
        "src_ip": f"192.168.1.{10 + ((row_number - 2) % 41)}",
        "dst_ip": "10.0.0.5",
        "src_mac": "00:1A:2B:3C:4D:5E",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_id": f"csv-replay-{row_number:06d}",
        "packet_count": 100,
        "capture_mode": "CSV_REPLAY",
        "src_port": 40000 + ((row_number - 2) % 1000),
        "dst_port": 80,
        "dominant_protocol": "TCP" if float(row["TCP"]) >= max(float(row["UDP"]), float(row["ICMP"])) else (
            "UDP" if float(row["UDP"]) >= float(row["ICMP"]) else "ICMP"
        ),
    }


def read_flows(csv_path: Path, limit: int | None) -> Iterator[dict[str, object]]:
    if not csv_path.is_file():
        raise FileNotFoundError(
            f"CSV file not found: {csv_path}\n"
            "Copy test_sample_500.csv into ml\\sample_data or pass --csv <path>."
        )
    with csv_path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        require_headers(reader.fieldnames or [])
        for row_number, row in enumerate(reader, start=2):
            if limit is not None and row_number - 1 > limit:
                break
            yield flow_from_row(row, row_number)


def send_batch(url: str, batch: list[dict[str, object]], timeout: float) -> None:
    response = requests.post(url, json={"data": batch}, timeout=timeout)
    if response.ok:
        result = response.json()
        print(
            f"Sent {result['processed_windows']} flows: "
            f"Benign={result['benign_count']} DoS={result['dos_count']} DDoS={result['ddos_count']}"
        )
        return
    print(f"API error {response.status_code}: {response.text}", file=sys.stderr)
    response.raise_for_status()


def simulate_traffic(args: argparse.Namespace) -> None:
    flows = read_flows(args.csv, args.limit)
    batch: list[dict[str, object]] = []
    sent = 0
    for flow in flows:
        batch.append(flow)
        if len(batch) == args.batch_size:
            if args.print_only:
                print(json.dumps({"data": batch}, indent=2))
                return
            send_batch(args.url, batch, args.timeout)
            sent += len(batch)
            batch.clear()
            if args.delay > 0:
                time.sleep(args.delay)

    if batch:
        if args.print_only:
            print(json.dumps({"data": batch}, indent=2))
        else:
            send_batch(args.url, batch, args.timeout)
            sent += len(batch)
    if args.print_only:
        print("Request preview complete.")
    else:
        print(f"Replay complete: {sent} flows sent.")


if __name__ == "__main__":
    try:
        simulate_traffic(parse_args())
    except (FileNotFoundError, ValueError, requests.RequestException) as exc:
        print(f"Simulator failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
