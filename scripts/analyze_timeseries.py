#!/usr/bin/env python3
"""
Analyze time-series sensor data from CSV exports or simulated inputs.

Capabilities
- Load one or more CSV files exported by scripts like sensor_extract.py
  (expected columns: timestamp, sensor_id, metric, value[, ...]).
- Alternatively, simulate multi-sensor data for quick experimentation.
- Compute per (sensor_id, metric) statistics: count, mean, std, min, max,
  quartiles (p25/p50/p75), and a z-score based anomaly count.
- Export per-group summaries as CSV and optional JSON.

Usage
  # Analyze exported CSVs
  python scripts/analyze_timeseries.py --inputs outputs/*.csv --zscore-threshold 3.0

  # Simulate 3 sensors with two metrics each for 2 days
  python scripts/analyze_timeseries.py --simulate --num-sensors 3 --num-days 2 --metrics temperature vibration
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd


@dataclass
class SimConfig:
    """Configuration for simulated multi-sensor datasets."""
    num_sensors: int = 3
    metrics: Sequence[str] = ("temperature", "vibration")
    num_days: int = 2
    readings_per_hour: int = 6  # every 10 minutes
    base_by_metric: dict = None  # type: ignore[assignment]
    std_by_metric: dict = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.base_by_metric is None:
            self.base_by_metric = {
                "temperature": 28.0,
                "vibration": 1.2,
                "pressure": 7.5,
            }
        if self.std_by_metric is None:
            self.std_by_metric = {
                "temperature": 0.9,
                "vibration": 0.15,
                "pressure": 0.4,
            }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments for analysis and simulation options."""
    parser = argparse.ArgumentParser(description="Analyze time-series sensor data.")
    parser.add_argument("--inputs", nargs="*", help="CSV files or glob patterns to analyze")
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR") or "outputs", help="Where to write summaries")
    parser.add_argument("--zscore-threshold", type=float, default=3.0, help="Z-score threshold for anomalies")
    parser.add_argument("--json", dest="write_json", action="store_true", help="Also write JSON summary")

    # Simulation options
    parser.add_argument("--simulate", action="store_true", help="Generate synthetic dataset instead of reading CSVs")
    parser.add_argument("--num-sensors", type=int, default=3, help="Number of sensors to simulate")
    parser.add_argument("--num-days", type=int, default=2, help="Days to simulate")
    parser.add_argument("--metrics", nargs="*", default=["temperature", "vibration"], help="Metrics to simulate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args(argv)


def ensure_output_dir(path: str) -> str:
    """Ensure output directory exists and return it."""
    os.makedirs(path, exist_ok=True)
    return path


def expand_inputs(patterns: Sequence[str]) -> List[str]:
    """Expand file globs into a unique, sorted list of paths."""
    files: List[str] = []
    for p in patterns:
        files.extend(glob.glob(p))
    return sorted(set(files))


def read_csvs(file_paths: Sequence[str]) -> pd.DataFrame:
    """Read and concatenate CSVs; validate required columns and parse timestamps."""
    frames: List[pd.DataFrame] = []
    for path in file_paths:
        df = pd.read_csv(path)
        # Normalize expected columns
        required = {"timestamp", "sensor_id", "metric", "value"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Missing columns in {path}: {sorted(missing)}")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        frames.append(df)
    if not frames:
        raise ValueError("No input files found.")
    return pd.concat(frames, ignore_index=True)


def simulate_dataset(cfg: SimConfig, seed: int) -> pd.DataFrame:
    """Generate synthetic readings including a diurnal component for temperature."""
    rng = np.random.default_rng(seed)
    start = datetime.now().replace(minute=0, second=0, microsecond=0)
    total_hours = cfg.num_days * 24
    total_points = total_hours * cfg.readings_per_hour
    dt_minutes = 60 // cfg.readings_per_hour

    records: List[Tuple[datetime, str, str, float]] = []

    for s in range(cfg.num_sensors):
        sensor_id = f"SENSOR_{s+1:02d}"
        for i in range(total_points):
            ts = start + timedelta(minutes=i * dt_minutes)
            hour = ts.hour + ts.minute / 60.0
            for metric in cfg.metrics:
                base = cfg.base_by_metric.get(metric, 1.0)
                std = cfg.std_by_metric.get(metric, 0.1)
                # Add a diurnal cycle for temperature-like signals
                diurnal = 0.0
                if metric == "temperature":
                    diurnal = 6.0 * np.sin(2 * np.pi * (hour / 24.0))
                value = base + diurnal + rng.normal(0.0, std)
                records.append((ts, sensor_id, metric, float(value)))

    df = pd.DataFrame.from_records(records, columns=["timestamp", "sensor_id", "metric", "value"])
    return df


def compute_group_stats(df: pd.DataFrame, zscore_threshold: float) -> pd.DataFrame:
    """Aggregate statistics and z-score anomaly counts per (sensor_id, metric)."""
    def _agg(group: pd.DataFrame) -> pd.Series:
        values = group["value"].astype(float)
        mean = float(values.mean())
        std = float(values.std(ddof=0))
        anomalies = 0
        if std > 0:
            z = (values - mean) / std
            anomalies = int((z.abs() >= zscore_threshold).sum())
        result = {
            "count": int(values.size),
            "mean": mean,
            "std": std,
            "min": float(values.min()),
            "p25": float(values.quantile(0.25)),
            "p50": float(values.quantile(0.50)),
            "p75": float(values.quantile(0.75)),
            "max": float(values.max()),
            "anomaly_count": anomalies,
        }
        return pd.Series(result)

    grouped = df.groupby(["sensor_id", "metric"], as_index=False).apply(_agg)
    # groupby.apply returns a MultiIndex sometimes; standardize
    grouped = grouped.reset_index(drop=True)
    return grouped


def export_summary(summary: pd.DataFrame, output_dir: str, base_name: str, write_json: bool) -> Tuple[str, Optional[str]]:
    """Write CSV and optional JSON summaries; return written paths."""
    csv_path = os.path.join(output_dir, f"{base_name}_summary.csv")
    summary.to_csv(csv_path, index=False)
    json_path = None
    if write_json:
        json_path = os.path.join(output_dir, f"{base_name}_summary.json")
        summary.to_json(json_path, orient="records", indent=2)
    return csv_path, json_path


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    outdir = ensure_output_dir(args.output_dir)

    if args.simulate:
        cfg = SimConfig(num_sensors=args.num_sensors, metrics=args.metrics, num_days=args.num_days)
        df = simulate_dataset(cfg, args.seed)
        base = f"sim_{args.num_sensors}sensors_{args.num_days}days"
    else:
        files = expand_inputs(args.inputs or [])
        df = read_csvs(files)
        base = "analyzed"

    # Basic sanity checks
    if df.empty:
        print("No data to analyze.")
        return 0
    if df["timestamp"].isna().any():
        print("Warning: some timestamps could not be parsed.")

    summary = compute_group_stats(df, args.zscore_threshold)
    csv_path, json_path = export_summary(summary, outdir, base, args.write_json)
    print(f"Wrote: {csv_path}")
    if json_path:
        print(f"Wrote: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


