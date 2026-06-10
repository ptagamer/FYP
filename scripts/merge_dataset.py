import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'data'

ORIGINAL_CSV  = DATA_DIR / 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
SPEAKEASY_CSV = DATA_DIR / 'speakeasy_training_data.csv'
OUTPUT_CSV    = DATA_DIR / 'merged_training_data.csv'

def merge_datasets(original_csv, speakeasy_csv, output_csv):
    print("Loading datasets...")
    df_orig = pd.read_csv(original_csv)
    df_spk  = pd.read_csv(speakeasy_csv)

    print(f"  Original  -> {len(df_orig):,} rows | Benign: {(df_orig['malware']==0).sum():,} | Malware: {(df_orig['malware']==1).sum():,}")
    print(f"  Speakeasy -> {len(df_spk):,} rows  | Benign: {(df_spk['malware']==0).sum():,} | Malware: {(df_spk['malware']==1).sum():,}")

    # Remove any hashes that appear in both (keep original's version)
    overlap = set(df_orig['hash'].astype(str)) & set(df_spk['hash'].astype(str))
    if overlap:
        print(f"\n  Removing {len(overlap)} duplicate hashes from speakeasy set.")
        df_spk = df_spk[~df_spk['hash'].astype(str).isin(overlap)]

    # Align columns — both have the same t_0..t_99 + hash + malware structure
    merged = pd.concat([df_orig, df_spk], ignore_index=True)
    merged.fillna(0, inplace=True)

    n_benign  = int((merged['malware'] == 0).sum())
    n_malware = int((merged['malware'] == 1).sum())
    ratio     = n_malware / n_benign

    print("\n" + "=" * 60)
    print("MERGED DATASET REPORT")
    print("=" * 60)
    print(f"  Total samples   : {len(merged):,}")
    print(f"  Benign  (0)     : {n_benign:,}")
    print(f"  Malware (1)     : {n_malware:,}")
    print(f"  Imbalance ratio : {ratio:.1f}:1 (malware:benign)")

    # Sequence density comparison
    seq_cols = [c for c in merged.columns if c.startswith('t_')]
    nz = (merged[seq_cols] != 0).sum(axis=1)
    print(f"  Avg non-zero API calls/sample: {nz.mean():.1f}")
    print(f"  Median non-zero API calls    : {nz.median():.0f}")
    print("=" * 60)

    merged.to_csv(output_csv, index=False)
    print(f"\nSaved -> {output_csv}")
    print("\nNext step: set DATASET_FILE = 'merged_training_data.csv' in main.py and run it.")

if __name__ == "__main__":
    merge_datasets(ORIGINAL_CSV, SPEAKEASY_CSV, OUTPUT_CSV)
