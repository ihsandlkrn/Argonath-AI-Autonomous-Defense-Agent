"""
data_pipeline.py — Autonomous Defense Agent (Final Production Version)
============================================================================
Updates:
  - Encoding issues fixed (Unicode normalization).
  - Heartbleed classified as DoS (Class 1).
  - Robust scaling + Smart sampling pipeline.
"""

import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
import warnings

warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR = r"C:\Users\ihsan\Desktop\Data"
MODEL_DIR = 'models'

MANUAL_FEATURES = [
    'Flow IAT Mean', 'Flow IAT Std', 'ACK Flag Count',
    'Down/Up Ratio', 'Init_Win_bytes_forward', 'Packet Length Variance'
]

# Maps raw CIC-IDS2017 label strings to integer class IDs.
LABEL_MAP = {
    'BENIGN': 0,
    'DoS Hulk': 1, 'DoS GoldenEye': 1, 'DoS slowloris': 1, 'DoS Slowhttptest': 1, 'Heartbleed': 1,
    'DDoS': 2,
    'PortScan': 3,
    'FTP-Patator': 4, 'SSH-Patator': 4,
    'Web Attack – Brute Force': 5, 'Web Attack – XSS': 5, 'Web Attack – Sql Injection': 5,
    'Bot': 6,
    'Infiltration': 7
}

CLASS_NAMES = {
    0: 'BENIGN', 1: 'DoS', 2: 'DDoS', 3: 'Port Scan',
    4: 'Brute Force', 5: 'Web Attack', 6: 'Bot', 7: 'Infiltration'
}


def plot_smote_distribution(y_before, y_after, class_names):
    """Plots class distribution before and after SMOTE side by side."""
    unique, counts_before = np.unique(y_before, return_counts=True)
    dict_before = dict(zip(unique, counts_before))

    unique, counts_after = np.unique(y_after, return_counts=True)
    dict_after = dict(zip(unique, counts_after))

    labels = [class_names.get(i, f"Class {i}") for i in unique]
    vals_before = [dict_before.get(i, 0) for i in unique]
    vals_after = [dict_after.get(i, 0) for i in unique]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    rects1 = ax.bar(x - width / 2, vals_before, width, label='Before SMOTE (Original)', color='lightcoral')
    rects2 = ax.bar(x + width / 2, vals_after, width, label='After SMOTE (Balanced)', color='steelblue')

    ax.set_ylabel('Sample Count (Log Scale)', fontsize=12)
    ax.set_title('Training Dataset: Class Distribution Before vs After SMOTE', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yscale('log')  # Log scale needed when class counts span several orders of magnitude
    ax.legend()

    plt.tight_layout()
    plt.savefig("SMOTE_Distribution.png", dpi=300)



# Usage: call after SMOTE inside train_model.py
# plot_smote_distribution(ym_train_original, ym_train_res, class_names)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: CLEANING & LABEL MAPPING
# ─────────────────────────────────────────────────────────────────────────────
def load_and_clean_data():
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    dataframes = []

    for f in csv_files:
        print(f"  Reading {os.path.basename(f)}...")
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            # Normalise Unicode dashes before label mapping
            df['Label'] = df['Label'].astype(str).str.replace('–', '–').str.strip()
            dataframes.append(df)
        except Exception as e:
            print(f"  ❌ Error: {e}")

    master_df = pd.concat(dataframes, ignore_index=True)
    master_df['Label'] = master_df['Label'].map(LABEL_MAP)
    master_df.dropna(subset=['Label'], inplace=True)
    # Remove rows with invalid (negative) IAT values
    master_df = master_df[(master_df['Flow IAT Mean'] >= 0) & (master_df['Flow IAT Std'] >= 0)]
    return master_df

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: SAMPLING & FEATURE CONSISTENCY
# ─────────────────────────────────────────────────────────────────────────────
def balance_and_scale(df):
    print("Step 3 — Applying SMOTE & Under-sampling (Dynamic Strategy)...")
    X = df[MANUAL_FEATURES]
    y = df['Label']

    class_counts = y.value_counts().to_dict()
    print(f"  Current distribution: {class_counts}")

    # BENIGN and dominant attack classes are down-sampled to reduce noise
    under_strategy = {0: 500000, 1: 100000, 2: 80000, 3: 80000}
    # Minority classes are up-sampled to 10k via SMOTE
    over_strategy = {4: 10000, 5: 10000, 6: 10000, 7: 10000}

    under_strategy = {k: v for k, v in under_strategy.items() if k in class_counts}
    over_strategy = {k: v for k, v in over_strategy.items() if k in class_counts and class_counts[k] < 10000}

    steps = [('under', RandomUnderSampler(sampling_strategy=under_strategy, random_state=42))]
    if over_strategy:
        steps.append(('smote', SMOTE(sampling_strategy=over_strategy, k_neighbors=2, random_state=42)))

    model = Pipeline(steps)

    y_before_smote = y.copy()
    X_res, y_res = model.fit_resample(X, y)

    print("  📊 Generating chart: SMOTE_Distribution.png")
    plot_smote_distribution(y_before_smote, y_res, CLASS_NAMES)

    print("Step 4 — Fitting RobustScaler...")
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X_res)

    final_df = pd.DataFrame(X_scaled, columns=MANUAL_FEATURES)
    final_df['Label'] = y_res.values

    return final_df, y_res, scaler

# ─────────────────────────────────────────────────────────────────────────────
# EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
def run_pipeline():
    master_df = load_and_clean_data()

    # Convert raw ACK count to ratio: ACK / total_packets (Scapy-compatible)
    total_pkts = master_df['Total Fwd Packets'] + master_df['Total Backward Packets']
    master_df['ACK Flag Count'] = (master_df['ACK Flag Count'] / (total_pkts + 1e-6)).clip(0, 1)

    balanced_df, y_res, scaler = balance_and_scale(master_df)
    balanced_df['Label'] = y_res.values

    # Export artifacts for agent_daemon.py and train_model.py
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    joblib.dump(MANUAL_FEATURES, os.path.join(MODEL_DIR, 'feature_names.pkl'))
    joblib.dump(CLASS_NAMES, os.path.join(MODEL_DIR, 'class_names.pkl'))
    balanced_df.to_csv(os.path.join(MODEL_DIR, 'balanced_data.csv'), index=False)
    print("✅ Pipeline complete. Features consistent, labels normalized.")

if __name__ == "__main__":
    run_pipeline()