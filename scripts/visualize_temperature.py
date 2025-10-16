#!/usr/bin/env python3
"""
Generate simulated temperature data and produce example plots using
Matplotlib and Seaborn. Useful for validating visualization styles
and reporting figures without accessing production data.

Outputs (written to OUTPUT_DIR or ./outputs):
- temperature_scatter.png: Scatter plot of temperature over time
- temperature_hist.png: Histogram with KDE
- temperature_box.png: Boxplot by hour of day
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Tuple

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


@dataclass
class SimConfig:
    num_days: int = 3
    readings_per_hour: int = 6  # every 10 minutes
    base_celsius: float = 28.0
    daily_amp: float = 6.0  # diurnal swing amplitude
    noise_std: float = 0.8


def ensure_output_dir() -> str:
    path = os.getenv("OUTPUT_DIR") or "outputs"
    os.makedirs(path, exist_ok=True)
    return path


def simulate_temperature(cfg: SimConfig, start: datetime) -> pd.DataFrame:
    total_hours = cfg.num_days * 24
    total_points = total_hours * cfg.readings_per_hour
    dt_minutes = 60 // cfg.readings_per_hour

    timestamps: List[datetime] = []
    values: List[float] = []

    for i in range(total_points):
        ts = start + timedelta(minutes=i * dt_minutes)
        hour = ts.hour + ts.minute / 60.0
        diurnal = cfg.daily_amp * np.sin(2 * np.pi * (hour / 24.0))
        noise = np.random.normal(0.0, cfg.noise_std)
        temp = cfg.base_celsius + diurnal + noise
        timestamps.append(ts)
        values.append(temp)

    df = pd.DataFrame({"timestamp": timestamps, "temperature_c": values})
    return df


def plot_scatter(df: pd.DataFrame, outdir: str) -> str:
    plt.figure(figsize=(10, 4))
    plt.scatter(df["timestamp"], df["temperature_c"], s=10, color="#1f77b4")
    plt.title("Simulated Temperature over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Temperature (°C)")
    plt.tight_layout()
    path = os.path.join(outdir, "temperature_scatter.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def plot_hist_kde(df: pd.DataFrame, outdir: str) -> str:
    plt.figure(figsize=(6, 4))
    sns.histplot(df["temperature_c"], kde=True, color="#2ca02c", bins=30)
    plt.title("Temperature Distribution")
    plt.xlabel("Temperature (°C)")
    plt.ylabel("Count")
    plt.tight_layout()
    path = os.path.join(outdir, "temperature_hist.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def plot_box_by_hour(df: pd.DataFrame, outdir: str) -> str:
    df2 = df.copy()
    df2["hour"] = df2["timestamp"].dt.hour
    plt.figure(figsize=(10, 4))
    sns.boxplot(data=df2, x="hour", y="temperature_c", color="#ff7f0e")
    plt.title("Temperature by Hour of Day")
    plt.xlabel("Hour")
    plt.ylabel("Temperature (°C)")
    plt.tight_layout()
    path = os.path.join(outdir, "temperature_box.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def main() -> int:
    outdir = ensure_output_dir()
    cfg = SimConfig()
    start = datetime.now().replace(minute=0, second=0, microsecond=0)
    df = simulate_temperature(cfg, start)

    scatter_path = plot_scatter(df, outdir)
    hist_path = plot_hist_kde(df, outdir)
    box_path = plot_box_by_hour(df, outdir)

    print("Generated:")
    print(scatter_path)
    print(hist_path)
    print(box_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


