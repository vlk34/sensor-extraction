#!/usr/bin/env python3
"""
Detect anomalies in time-series sensor data and visualize them.

This tool accepts one or more CSV inputs (expected columns: timestamp, sensor_id,
metric, value) or generates a simulated dataset. It applies either a z-score or
interquartile range (IQR) based detector per (sensor_id, metric), writes an
`anomaly_report.csv`, and optionally renders per-group figures that highlight
anomalous samples.

Detection methods:
- zscore (default): flags values with |(x - mean)/std| >= k
- iqr: flags values outside [Q1 - k*IQR, Q3 + k*IQR]

Typical usage:
  # Using CSVs
  python scripts/detect_and_plot.py --inputs outputs/*.csv --method zscore --threshold 3.0 --plot

  # Simulated data
  python scripts/detect_and_plot.py --simulate --num-sensors 2 --metrics temperature vibration --plot
"""

from __future__ import annotations

import argparse
import glob
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Sequence

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


@dataclass
class SimConfig:
    """Configuration for simulated datasets.

    Attributes:
        num_sensors: Number of synthetic sensors to generate.
        metrics: List of metric names (e.g., temperature, vibration).
        num_days: Window length in days.
        readings_per_hour: Sampling frequency per hour.
        base: Baseline value used for non-temperature metrics.
        std: Noise standard deviation for non-temperature metrics.
    """
    num_sensors: int = 2
    metrics: Sequence[str] = ("temperature",)
    num_days: int = 1
    readings_per_hour: int = 6
    base: float = 28.0
    std: float = 1.0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        argv: Optional list of CLI tokens; defaults to sys.argv.
    Returns:
        argparse.Namespace with parsed options.
    """
    parser = argparse.ArgumentParser(description="Detect and visualize anomalies in sensor data.")
    parser.add_argument("--inputs", nargs="*", help="CSV files or glob patterns")
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR") or "outputs", help="Output directory")
    parser.add_argument("--plot", action="store_true", help="Write per-group PNG plots")
    parser.add_argument("--method", choices=["zscore", "iqr"], default="zscore", help="Anomaly detection method")
    parser.add_argument("--threshold", type=float, default=3.0, help="Z-score or IQR multiplier (k)")
    parser.add_argument("--seed", type=int, default=7)

    # Simulation
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--num-sensors", type=int, default=2)
    parser.add_argument("--num-days", type=int, default=1)
    parser.add_argument("--metrics", nargs="*", default=["temperature"])
    return parser.parse_args(argv)


def ensure_output_dir(path: str) -> str:
    """Create output directory if missing and return its path."""
    os.makedirs(path, exist_ok=True)
    return path


def expand_inputs(patterns: Sequence[str]) -> List[str]:
    """Expand glob patterns into a unique, sorted list of file paths."""
    files: List[str] = []
    for p in patterns:
        files.extend(glob.glob(p))
    return sorted(set(files))


def read_csvs(file_paths: Sequence[str]) -> pd.DataFrame:
    """Load and concatenate CSV inputs with required columns.

    Raises:
        ValueError: if required columns are missing or no files were provided.
    """
    frames: List[pd.DataFrame] = []
    for path in file_paths:
        df = pd.read_csv(path)
        required = {"timestamp", "sensor_id", "metric", "value"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Missing columns in {path}: {sorted(missing)}")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        frames.append(df)
    if not frames:
        raise ValueError("No input files found.")
    return pd.concat(frames, ignore_index=True)


def simulate_dataset(cfg: SimConfig, seed: int, metrics: Sequence[str]) -> pd.DataFrame:
    """Create a synthetic multi-sensor dataset with basic diurnal effects."""
    rng = np.random.default_rng(seed)
    start = datetime.now().replace(minute=0, second=0, microsecond=0)
    total_hours = cfg.num_days * 24
    total_points = total_hours * cfg.readings_per_hour
    dt_minutes = 60 // cfg.readings_per_hour

    rows: List[List[object]] = []
    for s in range(cfg.num_sensors):
        sensor_id = f"SENSOR_{s+1:02d}"
        for i in range(total_points):
            ts = start + timedelta(minutes=i * dt_minutes)
            hour = ts.hour + ts.minute / 60
            for m in metrics:
                base = cfg.base
                std = cfg.std
                if m == "temperature":
                    base = 28.0 + 6.0 * np.sin(2 * np.pi * (hour / 24.0))
                    std = 1.0
                elif m == "vibration":
                    base = 1.2
                    std = 0.15
                elif m == "pressure":
                    base = 7.5
                    std = 0.4
                value = float(base + rng.normal(0.0, std))
                rows.append([ts, sensor_id, m, value])
    return pd.DataFrame(rows, columns=["timestamp", "sensor_id", "metric", "value"])


def detect_zscore(values: pd.Series, k: float) -> pd.Series:
    """Return boolean mask where values are anomalous by z-score >= k."""
    mean = values.mean()
    std = values.std(ddof=0)
    if std == 0 or np.isnan(std):
        return pd.Series(False, index=values.index)
    z = (values - mean) / std
    return z.abs() >= k


def detect_iqr(values: pd.Series, k: float) -> pd.Series:
    """Return boolean mask where values are outside the IQR envelope scaled by k."""
    q1 = values.quantile(0.25)
    q3 = values.quantile(0.75)
    iqr = q3 - q1
    if iqr == 0 or np.isnan(iqr):
        return pd.Series(False, index=values.index)
    lower = q1 - k * iqr
    upper = q3 + k * iqr
    return (values < lower) | (values > upper)


def flag_anomalies(df: pd.DataFrame, method: str, k: float) -> pd.DataFrame:
    """Annotate dataframe with an `is_anomaly` column per (sensor_id, metric)."""
    df = df.copy()
    def _flag(group: pd.DataFrame) -> pd.DataFrame:
        values = group["value"].astype(float)
        if method == "zscore":
            mask = detect_zscore(values, k)
        else:
            mask = detect_iqr(values, k)
        group = group.copy()
        group["is_anomaly"] = mask.values
        return group
    df = df.groupby(["sensor_id", "metric"], group_keys=False).apply(_flag)
    return df


def plot_group(df: pd.DataFrame, outdir: str, sensor_id: str, metric: str) -> Optional[str]:
    """Render a line plot with anomalies marked; return output PNG path if created."""
    if df.empty:
        return None
    plt.figure(figsize=(10, 4))
    sns.lineplot(data=df, x="timestamp", y="value", label="value", color="#1f77b4")
    anomalies = df[df["is_anomaly"]]
    if not anomalies.empty:
        plt.scatter(anomalies["timestamp"], anomalies["value"], color="#d62728", s=18, zorder=3, label="anomaly")
    plt.title(f"{sensor_id} - {metric}")
    plt.xlabel("timestamp")
    plt.ylabel("value")
    plt.legend(loc="best")
    plt.tight_layout()
    path = os.path.join(outdir, f"{sensor_id}_{metric}_anomalies.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def export_anomaly_report(df: pd.DataFrame, outdir: str) -> str:
    """Write `anomaly_report.csv` containing only anomalous rows and return its path."""
    report = df[df["is_anomaly"]].copy()
    path = os.path.join(outdir, "anomaly_report.csv")
    report.to_csv(path, index=False)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    outdir = ensure_output_dir(args.output_dir)

    if args.simulate:
        cfg = SimConfig(num_sensors=args.num_sensors, metrics=args.metrics, num_days=args.num_days)
        df = simulate_dataset(cfg, args.seed, args.metrics)
    else:
        files = expand_inputs(args.inputs or [])
        df = read_csvs(files)

    if df.empty:
        print("No data.")
        return 0

    df = df.sort_values(["sensor_id", "metric", "timestamp"]).reset_index(drop=True)
    df_flagged = flag_anomalies(df, args.method, args.threshold)

    if args.plot:
        printed_any = False
        for (sid, m), g in df_flagged.groupby(["sensor_id", "metric"]):
            path = plot_group(g, outdir, sid, m)
            if path and not printed_any:
                print("Wrote plots to:")
                printed_any = True
            if path:
                print(path)

    report_path = export_anomaly_report(df_flagged, outdir)
    print(f"Anomaly report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


