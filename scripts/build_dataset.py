import os
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.json_parser import flatten_speakeasy_json

# ── Configuration ──────────────────────────────────────────────────────────────

TARGET_DIRECTORY = PROJECT_ROOT / "archive" / "windows_emulation_trainset"
OUTPUT_FILE      = PROJECT_ROOT / "data" / "speakeasy_training_data.csv"

# Folders inside TARGET_DIRECTORY that contain benign (clean) samples.
# Everything else is treated as malware.
BENIGN_FOLDERS = {'report_clean', 'report_windows_syswow64'}

# Minimum number of non-zero API calls a sample must have to be kept.
# Samples below this threshold are almost entirely padding and carry no signal.
MIN_API_CALLS = 5

# ── Core builder ───────────────────────────────────────────────────────────────

def compile_dataset(root_dir, output_csv, min_api_calls=MIN_API_CALLS):
    print(f"Scanning: {root_dir}")
    print(f"Benign folders : {BENIGN_FOLDERS}")
    print(f"Min API calls  : {min_api_calls}")
    print("-" * 60)

    all_rows       = []
    skipped_sparse = 0
    skipped_error  = 0

    # Collect all JSON paths first so can show a total count
    all_files = [
        (root_path, fname)
        for root_path, _, files in os.walk(root_dir)
        for fname in files
        if fname.endswith('.json')
    ]
    total = len(all_files)
    print(f"Found {total:,} JSON files\n")

    for idx, (root_path, fname) in enumerate(all_files, 1):
        file_path   = os.path.join(root_path, fname)
        folder_name = os.path.basename(root_path)

        if idx % 500 == 0 or idx == total:
            print(f"  Progress: {idx}/{total} | Kept: {len(all_rows)} | "
                  f"Sparse: {skipped_sparse} | Errors: {skipped_error}",
                  end='\r')

        try:
            df_single = flatten_speakeasy_json(file_path)

            # ── Sparse filter ──────────────────────────────────────────────────
            seq_cols = [c for c in df_single.columns if c.startswith('t_')]
            nonzero  = int((df_single[seq_cols] != 0).sum(axis=1).iloc[0])
            if nonzero < min_api_calls:
                skipped_sparse += 1
                continue

            # ── Hash ───────────────────────────────────────────────────────────
            file_hash = fname.replace('.json', '')
            df_single.insert(0, 'hash', file_hash)

            # ── Label by folder name ───────────────────────────────────────────
            df_single['malware'] = 0 if folder_name in BENIGN_FOLDERS else 1

            all_rows.append(df_single)

        except Exception as exc:
            skipped_error += 1
            # Uncomment to debug parse failures:
            # print(f"\n  SKIP {file_path}: {exc}")

    print()  # flush the \r progress line

    # ── Assemble ───────────────────────────────────────────────────────────────
    if not all_rows:
        print("\nNo valid samples collected. Check your TARGET_DIRECTORY path.")
        sys.exit(1)

    print(f"\nCombining {len(all_rows):,} samples...")
    final = pd.concat(all_rows, ignore_index=True)
    final.fillna(0, inplace=True)

    n_benign  = int((final['malware'] == 0).sum())
    n_malware = int((final['malware'] == 1).sum())

    # ── Report ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("DATASET REPORT")
    print("=" * 60)
    print(f"  Total kept      : {len(final):,}")
    print(f"  Benign  (0)     : {n_benign:,}")
    print(f"  Malware (1)     : {n_malware:,}")
    print(f"  Skipped sparse  : {skipped_sparse:,}")
    print(f"  Skipped errors  : {skipped_error:,}")

    if n_benign == 0:
        print("\n  WARNING: Still zero benign samples!")
        print("  Check that your archive actually contains 'report_clean'")
        print("  or 'report_windows_syswow64' subfolders with JSON files.")
    else:
        ratio = n_malware / n_benign
        print(f"  Imbalance ratio : {ratio:.0f}:1 (malware:benign)")
        if ratio > 20:
            print("  WARNING: High imbalance — SMOTE in main.py will compensate,")
            print("  but consider collecting more benign samples if accuracy is poor.")

    print("=" * 60)
    final.to_csv(output_csv, index=False)
    print(f"\nSaved -> {output_csv}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    compile_dataset(TARGET_DIRECTORY, OUTPUT_FILE)
