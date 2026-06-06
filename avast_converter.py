import json
import pandas as pd
import os

# 1. Setup the paths (using the one we just found!)
INPUT_JSONL = r"avast_data\avast_full_sequences_labeled_canonical_subset5_seed42.jsonl"
OUTPUT_CSV = "avast_blind_test.csv"

def convert_avast_to_nebula(limit=100):
    print(f"--- Starting High-Effort Conversion (Limit: {limit} samples) ---")
    
    extracted_data = []

    if not os.path.exists(INPUT_JSONL):
        print("Error: JSONL file not found at the specified path!")
        return

    with open(INPUT_JSONL, 'r') as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            
            # Load the raw JSON line
            item = json.loads(line)
            
            # Avast uses 'sequence' for the API calls and 'label' for malware (1) or benign (0)
            sequence = item.get('sequence', [])
            label = item.get('label', 0)
            file_hash = item.get('sha256', f"hash_{i}")

            # We only need the first 100 calls to match your model's training
            # If the sequence is shorter, we pad it with 0s
            sequence_100 = (sequence[:100] + [0] * 100)[:100]
            
            # Create a dictionary for this row
            row = {'hash': file_hash}
            for idx, api_id in enumerate(sequence_100):
                row[f't_{idx}'] = api_id
            
            row['malware'] = label
            extracted_data.append(row)
            
            if (i + 1) % 10 == 0:
                print(f"Processed {i + 1} samples...")

    # 2. Convert to DataFrame and Save
    df = pd.DataFrame(extracted_data)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSUCCESS! Created '{OUTPUT_CSV}' with {len(df)} blind test samples.")
    print("You can now select this file in your GUI!")

if __name__ == "__main__":
    convert_avast_to_nebula()