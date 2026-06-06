import pandas as pd
import os

# Your main dataset file
MAIN_DATASET = 'dynamic_api_call_sequence_per_malware_100_0_306.csv'

def create_demo_samples():
    if not os.path.exists(MAIN_DATASET):
        print(f"Error: {MAIN_DATASET} not found.")
        return

    print("Loading main dataset...")
    df = pd.read_csv(MAIN_DATASET)

    # 1. Extract a Malicious Sample (malware == 1)
    malicious_df = df[df['malware'] == 1].sample(n=1, random_state=42)
    malicious_df.to_csv('demo_malicious_payload.csv', index=False)
    # The .index property stores the original row number (0-indexed)
    print(f"Created: demo_malicious_payload.csv (Extracted from Original Row Index: {malicious_df.index[0]})")

    # 2. Extract a Benign Sample (malware == 0)
    benign_df = df[df['malware'] == 0].sample(n=1, random_state=42)
    benign_df.to_csv('demo_benign_software.csv', index=False)
    print(f"Created: demo_benign_software.csv (Extracted from Original Row Index: {benign_df.index[0]})")

    print("\nSuccess! You can now upload these files directly into your dashboard.")

if __name__ == "__main__":
    create_demo_samples()