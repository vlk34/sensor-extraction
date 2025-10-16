Sensor data extraction utility

Overview
A command-line tool for extracting historical sensor data from a read-only SQL Server replica, running light quality checks, calculating basic stats, flagging simple anomalies, and exporting results for quick review and reporting.

Files

- scripts/sensor_extract.py: Main CLI utility
- requirements.txt: Minimal Python dependencies
- scripts/visualize_temperature.py: Simulated temperature plots (Matplotlib + Seaborn)
- scripts/analyze_timeseries.py: Per-sensor/metric statistics and anomaly counts

Prerequisites

- Windows with an appropriate Microsoft ODBC Driver for SQL Server (e.g., ODBC Driver 17 or 18)
- Python 3.10+
- Network access to the non-production SQL Server instance
- Read-only SQL credentials

Install

1. Create and activate a virtual environment (recommended)
   python -m venv .venv
   .venv\\Scripts\\activate

2. Install dependencies
   pip install -r requirements.txt

Configure environment
Set the following environment variables (examples for Windows CMD):
setx DB_SERVER "tcp:127.0.0.1,1433"
setx DB_NAME "PlantReplica"
setx DB_USER "readonly_user"
setx DB_PASSWORD "<secret>"
setx OUTPUT_DIR "%USERPROFILE%\\Staj\\outputs"

Optional overrides:

- DB_DRIVER: ODBC driver name, default "ODBC Driver 17 for SQL Server"
- DB_TIMEOUT_SECONDS: default 15

Schema assumption
Adjust queries in scripts/sensor_extract.py to your schema if needed. Default expectation:

- Table: dbo.SensorReadings(timestamp, sensor_id, metric, value)

Usage
Example: extract temperature data for a sensor and export a chart.
python scripts/sensor_extract.py ^
--sensor-id TURBINE_A_BRG1 ^
--metric temperature ^
--start 2025-08-01T00:00:00 ^
--end 2025-08-07T23:59:59 ^
--plot

Visualization script (simulated data)
Generate a few quick figures without accessing database data:
python scripts/visualize_temperature.py
Outputs are written under OUTPUT_DIR or ./outputs:

- temperature_scatter.png (scatter over time)
- temperature_hist.png (histogram with KDE)
- temperature_box.png (boxplot by hour)

Analyze time-series summaries
Compute per-sensor/metric statistics from existing CSVs or simulated data:

# Analyze CSV exports

python scripts/analyze_timeseries.py --inputs outputs/\*.csv --zscore-threshold 3.0 --json

# Simulate data (3 sensors, 2 days, temperature & vibration)

python scripts/analyze_timeseries.py --simulate --num-sensors 3 --num-days 2 --metrics temperature vibration --json

Outputs:

- _\_summary.csv and optional _\_summary.json in OUTPUT_DIR or ./outputs

CLI options:

- --sensor-id: Sensor identifier (required)
- --metric: temperature | vibration | pressure | any (required)
- --start, --end: ISO datetimes (required)
- --limit: Max rows (default 200000)
- --output-dir: Where CSV/PNG is written (default OUTPUT_DIR or ./outputs)
- --plot: Save a PNG plot (if matplotlib is installed)
- --zscore-threshold: Anomaly threshold (default 3.0)

Outputs

- CSV: <sensor>_<metric>_<start>\_<end>.csv with columns
  timestamp, sensor_id, metric, value, zscore, is_anomaly
- PNG: optional line chart with anomalies highlighted

Troubleshooting

- If connection fails: verify DB_SERVER, DB_NAME, driver installed, firewall, and credentials.
- If query returns zero rows: check sensor id/metric names, time window, and table/column names.
- If matplotlib/pandas not installed: run pip install -r requirements.txt.

Security notes

- Keep credentials in environment variables; avoid committing secrets to source control.
- Use read-only SQL accounts for data extraction.
