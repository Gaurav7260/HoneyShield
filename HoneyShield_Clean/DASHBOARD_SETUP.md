# HoneyShield Dashboard Setup

## 1. Open the project folder
Extract `HoneyShield_Source_Clean_2026-10-25.zip`, then open the `HoneyShield` folder in Terminal.

## 2. Activate the virtual environment
If you already created `.venv` in this folder:

```bash
source .venv/bin/activate
```

If not, create one and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Start the dashboard

```bash
streamlit run app/dashboard.py
```

Streamlit should open a local browser tab. If it does not, use the local URL printed in Terminal (usually `http://localhost:8501`). Stop the dashboard with `Control+C` in Terminal.

## Dashboard sections
- **Overview:** headline pilot outcomes and selected guard evaluation metrics.
- **Boundary experiment:** compare baseline, output-only, and boundary-plus-output configurations.
- **Guard evaluation:** inspect holdout, benign stress, and positive stress results.
- **Latency & reproducibility:** guard-only latency and manifest table.
- **Explore raw data:** browse included CSVs and download filtered rows.

## Important interpretation note
This dashboard visualizes saved CSVs; it does not automatically rerun the experiments. The dashboard is a research summary, not a live security operations console. Its metrics describe synthetic and controlled test cases only.
