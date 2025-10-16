#!/usr/bin/env python3
"""
Sensor data extraction and basic anomaly detection utility.

Features:
- Pulls time-series sensor signals (e.g., temperature, vibration, pressure) for
  a given time window from a SQL Server database (read-only recommended).
- Performs validation, computes basic statistics, flags simple anomalies,
  and exports CSV and optional charts for quick review.

Security and configuration:
- Uses environment variables for credentials and configuration.
- Avoids printing secrets; supports least-privilege accounts.

Data model assumptions (adapt as needed):
- Table: dbo.SensorReadings
  Columns:
    - timestamp (datetime2)
    - sensor_id (nvarchar)
    - metric (nvarchar) e.g., 'temperature', 'vibration', 'pressure'
    - value (float)

Usage example (Windows CMD):
  setx DB_SERVER "tcp:127.0.0.1,1433"
  setx DB_NAME "PlantReplica"
  setx DB_USER "readonly_user"
  setx DB_PASSWORD "<secret>"
  setx OUTPUT_DIR "C:\\Users\\volka\\Staj\\outputs"

  python scripts/sensor_extract.py \
    --sensor-id TURBINE_A_BRG1 \
    --metric temperature \
    --start "2025-08-01T00:00:00" \
    --end   "2025-08-07T23:59:59" \
    --plot

Dependencies: see requirements.txt
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import os
import sys
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

# Third-party imports are optional until actually used; we guard import errors
try:
    import pyodbc  # type: ignore
except Exception as exc:  # pragma: no cover - helpful message if missing
    pyodbc = None  # type: ignore
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None  # type: ignore

try:
    import matplotlib.pyplot as plt  # type: ignore
except Exception:
    plt = None  # type: ignore


@dataclasses.dataclass
class DbConfig:
    server: str
    database: str
    user: str
    password: str
    driver: str = "ODBC Driver 17 for SQL Server"  # Common on Windows
    timeout_seconds: int = 15


def read_env_config() -> DbConfig:
    missing: List[str] = []
    server = os.getenv("DB_SERVER") or ""
    if not server:
        missing.append("DB_SERVER")
    database = os.getenv("DB_NAME") or ""
    if not database:
        missing.append("DB_NAME")
    user = os.getenv("DB_USER") or ""
    if not user:
        missing.append("DB_USER")
    password = os.getenv("DB_PASSWORD") or ""
    if not password:
        missing.append("DB_PASSWORD")

    if missing:
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    driver = os.getenv("DB_DRIVER") or "ODBC Driver 17 for SQL Server"
    timeout = int(os.getenv("DB_TIMEOUT_SECONDS") or 15)
    return DbConfig(
        server=server, database=database, user=user, password=password,
        driver=driver, timeout_seconds=timeout
    )


def build_connection_string(cfg: DbConfig) -> str:
    # Trusted_Connection=no ensures SQL auth; MARS off for simplicity.
    return (
        f"DRIVER={{{{ {cfg.driver} }}}};"
        f"SERVER={cfg.server};"
        f"DATABASE={cfg.database};"
        f"UID={cfg.user};PWD={cfg.password};"
        f"TrustServerCertificate=yes;"
        f"Encrypt=yes;"
        f"Connection Timeout={cfg.timeout_seconds};"
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract sensor readings from SQL Server and do basic QC/anomaly flags.",
    )
    parser.add_argument("--sensor-id", required=True, help="Sensor identifier to query")
    parser.add_argument(
        "--metric", required=True, choices=["temperature", "vibration", "pressure", "any"],
        help="Metric to filter; 'any' returns all metrics for sensor"
    )
    parser.add_argument("--start", required=True, help="Start ISO datetime, e.g. 2025-08-01T00:00:00")
    parser.add_argument("--end", required=True, help="End ISO datetime, e.g. 2025-08-07T23:59:59")
    parser.add_argument("--limit", type=int, default=200000, help="Max rows to return (def 200k)")
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR") or "outputs", help="Directory for exports")
    parser.add_argument("--plot", action="store_true", help="Also export a PNG chart if matplotlib is available")
    parser.add_argument("--zscore-threshold", type=float, default=3.0, help="Z-score threshold for anomalies")
    return parser.parse_args(argv)


def ensure_output_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def parse_iso_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO datetime: {value}") from exc


def query_readings(conn, sensor_id: str, metric: str, start_ts: datetime, end_ts: datetime, limit: int):
    params: List[object] = [sensor_id, start_ts, end_ts]
    metric_filter = ""
    if metric != "any":
        metric_filter = " AND r.metric = ?"
        params.insert(1, metric)

    sql = (
        "SELECT TOP (?) r.timestamp, r.sensor_id, r.metric, r.value\n"
        "FROM dbo.SensorReadings AS r\n"
        "WHERE r.sensor_id = ?" + metric_filter + " AND r.timestamp >= ? AND r.timestamp <= ?\n"
        "ORDER BY r.timestamp ASC"
    )
    # TOP (?) must be first parameter in pyodbc binding order
    params = [limit] + params

    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    return rows


def to_dataframe(rows) -> "pd.DataFrame":  # type: ignore[name-defined]
    if pd is None:
        raise RuntimeError("pandas is required for dataframe operations. Please install dependencies.")
    df = pd.DataFrame.from_records(rows, columns=["timestamp", "sensor_id", "metric", "value"])
    df.sort_values("timestamp", inplace=True)
    return df


def compute_stats(df) -> Tuple[float, float]:
    mean = float(df["value"].mean())
    std = float(df["value"].std(ddof=0))
    return mean, std


def flag_anomalies(df, zscore_threshold: float) -> "pd.DataFrame":  # type: ignore[name-defined]
    if pd is None:
        raise RuntimeError("pandas is required for anomaly flagging.")
    mean, std = compute_stats(df)
    if std == 0.0:
        df = df.copy()
        df["zscore"] = 0.0
        df["is_anomaly"] = False
        return df
    df = df.copy()
    df["zscore"] = (df["value"] - mean) / std
    df["is_anomaly"] = df["zscore"].abs() >= zscore_threshold
    return df


def export_csv(df, output_dir: str, base_name: str) -> str:
    path = os.path.join(output_dir, f"{base_name}.csv")
    df.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)
    return path


def export_plot(df, output_dir: str, base_name: str) -> Optional[str]:
    if plt is None:
        return None
    plt.figure(figsize=(10, 4))
    plt.plot(df["timestamp"], df["value"], label="value", color="#1f77b4")
    if "is_anomaly" in df.columns:
        anomalous = df[df["is_anomaly"]]
        if not anomalous.empty:
            plt.scatter(anomalous["timestamp"], anomalous["value"], color="#d62728", label="anomaly", s=12, zorder=3)
    plt.title("Sensor readings")
    plt.xlabel("timestamp")
    plt.ylabel("value")
    plt.legend(loc="best")
    plt.tight_layout()
    path = os.path.join(output_dir, f"{base_name}.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def main(argv: Optional[List[str]] = None) -> int:
    if _IMPORT_ERROR is not None:
        sys.stderr.write(
            "pyodbc is not installed or failed to import. Install dependencies from requirements.txt.\n"
        )
        return 2

    args = parse_args(argv)

    # Basic argument validation
    try:
        start_ts = parse_iso_dt(args.start)
        end_ts = parse_iso_dt(args.end)
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    if start_ts >= end_ts:
        sys.stderr.write("Start datetime must be earlier than end datetime.\n")
        return 2
    if args.limit <= 0:
        sys.stderr.write("--limit must be positive.\n")
        return 2

    output_dir = ensure_output_dir(args.output_dir)

    try:
        cfg = read_env_config()
    except RuntimeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2

    conn_str = build_connection_string(cfg)

    # Connect and query with robust error messaging (without leaking secrets)
    try:
        conn = pyodbc.connect(conn_str)  # type: ignore[arg-type]
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(
            "Failed to connect to SQL Server. Check DB_SERVER/DB_NAME/driver/network.\n"
        )
        sys.stderr.write(f"Driver: {cfg.driver}\nServer: {cfg.server}\nDatabase: {cfg.database}\n")
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    try:
        rows = query_readings(conn, args.sensor_id, args.metric, start_ts, end_ts, args.limit)
    except Exception as exc:  # pragma: no cover
        sys.stderr.write("Query failed. Verify table/columns/permissions and time range.\n")
        sys.stderr.write(f"Error: {exc}\n")
        try:
            conn.close()
        except Exception:
            pass
        return 1

    conn.close()

    if not rows:
        sys.stdout.write("No rows returned for given filters.\n")
        return 0

    try:
        df = to_dataframe(rows)
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"Failed to convert results to DataFrame: {exc}\n")
        return 1

    df_flagged = flag_anomalies(df, args.zscore_threshold)

    base = (
        f"{args.sensor_id}_{args.metric}_{start_ts.strftime('%Y%m%dT%H%M%S')}"
        f"_{end_ts.strftime('%Y%m%dT%H%M%S')}"
    )

    csv_path = export_csv(df_flagged, output_dir, base)
    sys.stdout.write(f"Exported CSV: {csv_path}\n")

    if args.plot:
        img_path = export_plot(df_flagged, output_dir, base)
        if img_path:
            sys.stdout.write(f"Exported plot: {img_path}\n")
        else:
            sys.stdout.write("matplotlib not available; skipping plot.\n")

    # Summary to console
    mean, std = compute_stats(df)
    anomalies = int(df_flagged["is_anomaly"].sum()) if "is_anomaly" in df_flagged.columns else 0
    sys.stdout.write(
        f"Rows: {len(df)}, mean: {mean:.3f}, std: {std:.3f}, anomalies: {anomalies}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


