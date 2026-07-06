import pandas as pd
import os
from pathlib import Path

# Main dataset file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'data'
MAIN_DATASET = DATA_DIR / 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
MALICIOUS_DEMO_FILE = DATA_DIR / 'demo_malicious_payload.csv'
BENIGN_DEMO_FILE = DATA_DIR / 'demo_benign_software.csv'

def create_demo_samples(source_csv=None):
    """Extract one malicious and one benign sample from a dataset CSV.

    Args:
        source_csv: Path to a CSV file containing a 'malware' column.
                    If None, falls back to the default MAIN_DATASET.

    Returns:
        A tuple of (malicious_demo_path, benign_demo_path) on success,
        or None on failure.
    """
    dataset_path = Path(source_csv) if source_csv else MAIN_DATASET

    if not dataset_path.exists():
        print(f"Error: {dataset_path} not found.")
        return None

    print(f"Loading dataset: {dataset_path.name}...")
    df = pd.read_csv(dataset_path)

    if 'malware' not in df.columns:
        raise ValueError(
            f"The selected CSV does not contain a 'malware' column.\n"
            f"Found columns: {', '.join(df.columns[:10])}"
        )

    malicious_rows = df[df['malware'] == 1]
    benign_rows = df[df['malware'] == 0]

    if malicious_rows.empty:
        raise ValueError("No malicious samples (malware=1) found in the dataset.")
    if benign_rows.empty:
        raise ValueError("No benign samples (malware=0) found in the dataset.")

    # 1. Extract a Malicious Sample (malware == 1)
    malicious_df = malicious_rows.sample(n=1)
    malicious_df.to_csv(MALICIOUS_DEMO_FILE, index=False)
    # The .index property stores the original row number (0-indexed)
    print(f"Created: {MALICIOUS_DEMO_FILE} (Extracted from Original Row Index: {malicious_df.index[0]})")

    # 2. Extract a Benign Sample (malware == 0)
    benign_df = benign_rows.sample(n=1)
    benign_df.to_csv(BENIGN_DEMO_FILE, index=False)
    print(f"Created: {BENIGN_DEMO_FILE} (Extracted from Original Row Index: {benign_df.index[0]})")

    print("\nSuccess! You can now upload these files directly into your dashboard.")
    return (str(MALICIOUS_DEMO_FILE), str(BENIGN_DEMO_FILE))


if __name__ == "__main__":
    create_demo_samples()
