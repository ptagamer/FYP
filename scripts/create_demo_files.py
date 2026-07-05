import pandas as pd
import os
from pathlib import Path

# Main dataset file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'data'
MAIN_DATASET = DATA_DIR / 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
MALICIOUS_DEMO_FILE = DATA_DIR / 'demo_malicious_payload.csv'
BENIGN_DEMO_FILE = DATA_DIR / 'demo_benign_software.csv'

def create_demo_samples():
    if not os.path.exists(MAIN_DATASET):
        print(f"Error: {MAIN_DATASET} not found.")
        return

    print("Loading main dataset...")
    df = pd.read_csv(MAIN_DATASET)

    # 1. Extract a Malicious Sample (malware == 1)
    malicious_df = df[df['malware'] == 1].sample(n=1, random_state=42)
    malicious_df.to_csv(MALICIOUS_DEMO_FILE, index=False)
    # The .index property stores the original row number (0-indexed)
    print(f"Created: {MALICIOUS_DEMO_FILE} (Extracted from Original Row Index: {malicious_df.index[0]})")

    # 2. Extract a Benign Sample (malware == 0)
    benign_df = df[df['malware'] == 0].sample(n=1, random_state=42)
    benign_df.to_csv(BENIGN_DEMO_FILE, index=False)
    print(f"Created: {BENIGN_DEMO_FILE} (Extracted from Original Row Index: {benign_df.index[0]})")

    print("\nSuccess! You can now upload these files directly into your dashboard.")

if __name__ == "__main__":
    create_demo_samples()
