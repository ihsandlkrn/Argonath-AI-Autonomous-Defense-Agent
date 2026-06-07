"""
all_features_profiler.py — Comprehensive Dataset Profiler
══════════════════════════════════════════════════════════════════════════
This script reads the raw CIC-IDS2017 dataset and calculates the exact
mathematical mean for EVERY available numeric feature across all attack classes.

It exports a massive "Ground Truth" table to a CSV file so the engineer
can manually inspect and select the best features.
"""

import pandas as pd
import numpy as np
import glob
import os
import warnings

warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR = r"C:\Users\ihsan\Desktop\Data"
OUTPUT_CSV = "all_features_raw_profiles.csv"

LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS',
    'DDoS': 'DDoS',
    'PortScan': 'Port Scan',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force',
    'Web Attack \xbd Brute Force': 'Web Attack', 'Web Attack \xbd XSS': 'Web Attack',
    'Web Attack \xbd Sql Injection': 'Web Attack',
    'Bot': 'Bot',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Web Attack'
}


def load_and_profile_all_features():
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not csv_files:
        print(f"❌ ERROR: No CSV files found in {DATA_DIR}")
        return

    print(f"🔍 Loading {len(csv_files)} raw dataset files... (This may take a minute)")

    dataframes = []
    for f in csv_files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()  # Clean whitespace in column names
        dataframes.append(df)

    master_df = pd.concat(dataframes, ignore_index=True)
    print(f"  ✅ Loaded {len(master_df):,} total rows.")

    # 1. Map classification labels
    master_df['Attack_Type'] = master_df['Label'].map(LABEL_MAP)
    master_df.dropna(subset=['Attack_Type'], inplace=True)

    # 2. Remove unnecessary/string-based identifier columns
    drop_cols = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP',
                 'Destination Port', 'Timestamp', 'Label']
    master_df.drop(columns=[c for c in drop_cols if c in master_df.columns], inplace=True, errors='ignore')

    # 3. Clean infinity values
    master_df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Select only numeric columns
    numeric_cols = master_df.select_dtypes(include=[np.number]).columns.tolist()

    # Drop rows containing NaN values
    master_df.dropna(subset=numeric_cols, inplace=True)

    print(f"\n🧮 Calculating raw averages for {len(numeric_cols)} features...")

    # 4. Group by attack type and calculate mean for all numeric columns
    profile_df = master_df.groupby('Attack_Type')[numeric_cols].mean().round(2)

    # 5. Transpose for better terminal readability
    display_df = profile_df.T

    sep = "=" * 90
    print(f"\n{sep}")
    print(f"📊 ALL FEATURES GROUND TRUTH ({len(numeric_cols)} Features)")
    print(sep)

    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_rows', 100)  # Show all rows
    pd.set_option('display.width', 200)
    print(display_df.to_string())
    print(sep)

    print("\n💾 Exporting to CSV...")
    display_df.to_csv(OUTPUT_CSV, sep=';', decimal=',')
    print(f"  ✅ Saved successfully to: {OUTPUT_CSV}")
    print(
        "  💡 TIP: The terminal may truncate the output. Open the CSV file in Excel for full inspection.")


if __name__ == "__main__":
    load_and_profile_all_features()