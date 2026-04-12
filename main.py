import pandas as pd
import hashlib
import matplotlib.pyplot as plt
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash to ensure data integrity."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def train_nebula_model():
    file_name = 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
    
    # 1. ACTIVE INTEGRITY CHECK
    EXPECTED_HASH = "11005ff6f5007bfee7d60bd0dc2e787f4e77b46f3b0a3d09424421c5339a8406"
    
    if not os.path.exists(file_name):
        print(f"ERROR: Dataset {file_name} not found.")
        return

    current_hash = calculate_sha256(file_name)
    
    if current_hash != EXPECTED_HASH:
        # Halt the modular pipeline if integrity is compromised 
        print(f"CRITICAL ERROR: Dataset integrity compromised!")
        print(f"Expected: {EXPECTED_HASH}")
        print(f"Found:    {current_hash}")
        return 
    else:
        print(f"SUCCESS: Data Integrity Verified. (SHA-256: {current_hash})")

    # 2. Loading the dataset
    df = pd.read_csv(file_name)
    X = df.drop(['hash', 'malware'], axis=1)
    y = df['malware']

    # 3. Model Training with Balanced Weights
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)

    # 4. Results Output
    predictions = model.predict(X_test)
    print("\n--- Nebula Detection Performance ---")
    print(classification_report(y_test, predictions))

    # 5. Feature Importance Visualization & Export
    importances = model.feature_importances_
    indices = np.argsort(importances)[-10:] 

    plt.figure(figsize=(10,6))
    plt.title('Nebula Engine: Top 10 Behavioral Features (API Sequences)')
    plt.barh(range(len(indices)), importances[indices], color='teal', align='center')
    plt.yticks(range(len(indices)), [X.columns[i] for i in indices])
    plt.xlabel('Relative Importance')
    plt.tight_layout()
    
    # Automatically save for FYP report
    plt.savefig('nebula_feature_importance.png', dpi=300)
    print("\nFeature importance chart saved as 'nebula_feature_importance.png'")
    plt.show()

    # 6. Save the trained model for the future GUI
    joblib.dump(model, 'nebula_rf_model.pkl')
    print("\nModel saved successfully as 'nebula_rf_model.pkl'")

if __name__ == "__main__":
    train_nebula_model()

# Check if file exists on disk
if os.path.exists('nebula_rf_model.pkl'):
    print("SUCCESS: File 'nebula_rf_model.pkl' found on disk.")
    
    # Try loading it back into memory
    loaded_model = joblib.load('nebula_rf_model.pkl')
    print("SUCCESS: Model reloaded into memory perfectly.")
else:
    print("ERROR: Model file was not found. Check your folder permissions.")