"""
clean_raw_data.py — Data Deduplication & Pre-processing Utility
================================================================
Scans raw CSV files, removes duplicate rows (data leakage risk),
and saves cleaned versions to a new folder without modifying originals.
"""

import os
import glob
import pandas as pd

RAW_DATA_DIR   = r"C:\Users\ihsan\Desktop\Data"
CLEAN_DATA_DIR = r"C:\Users\ihsan\Desktop\Cleaned_Data"


def clean_and_transfer_files():
    print("🧹 Raw Data Cleaning & Deduplication Started...\n")

    if not os.path.exists(CLEAN_DATA_DIR):
        os.makedirs(CLEAN_DATA_DIR)
        print(f"📁 Created output folder: {CLEAN_DATA_DIR}")

    csv_files = glob.glob(os.path.join(RAW_DATA_DIR, "*.csv"))

    if not csv_files:
        print(f"❌ Error: No CSV files found in {RAW_DATA_DIR}.")
        return

    total_original = 0
    total_cleaned  = 0

    for file in csv_files:
        filename = os.path.basename(file)
        print(f"Processing: {filename}...")

        try:
            df = pd.read_csv(file, low_memory=False)
            original_rows = len(df)
            total_original += original_rows

            # Strip whitespace from column names to prevent downstream errors
            df.columns = df.columns.str.strip()

            # Remove duplicate rows, keeping the first occurrence
            df_cleaned  = df.drop_duplicates(keep='first')
            cleaned_rows = len(df_cleaned)
            total_cleaned += cleaned_rows

            duplicates_removed = original_rows - cleaned_rows

            save_path = os.path.join(CLEAN_DATA_DIR, filename)
            df_cleaned.to_csv(save_path, index=False)

            print(f"  ├─ Original rows  : {original_rows:,d}")
            print(f"  ├─ Duplicates removed: {duplicates_removed:,d}")
            print(f"  └─ Remaining rows : {cleaned_rows:,d}\n")

        except Exception as e:
            print(f"  ❌ Error processing {filename}: {e}\n")

    print("=" * 50)
    print("✅ ALL FILES PROCESSED")
    print("=" * 50)
    print(f"Total original rows : {total_original:,d}")
    print(f"Total clean rows    : {total_cleaned:,d}")
    print(f"Total duplicates    : {total_original - total_cleaned:,d}")
    print(f"\nCleaned files saved to:\n{CLEAN_DATA_DIR}")


if __name__ == "__main__":
    clean_and_transfer_files()