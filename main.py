import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Import the modular logic from the updated processors.py
from processors import BehavioralDataProcessor, MalwareFeatureExtractor

# The "Golden Hash" 
EXPECTED_HASH = "11005ff6f5007bfee7d60bd0dc2e787f4e77b46f3b0a3d09424421c5339a8406"
MODEL_FILE = "nebula_rf_model.pkl"

def train_nebula_model(file_name):
    """
    TRAINING PHASE: Coordinates data ingestion, feature extraction (F3), and model training.
    Run this file directly to generate the updated .pkl model.
    """
    print(f"\n--- INITIATING NEBULA TRAINING SEQUENCE ---")
    processor = BehavioralDataProcessor(expected_hash=EXPECTED_HASH)
    extractor = MalwareFeatureExtractor()
    
    if not os.path.exists(file_name):
        print(f"ERROR: Dataset {file_name} not found.")
        return

    try:
        processor.verify_integrity(file_name)
    except ValueError as e:
        print(f"CRITICAL ERROR: {e}")
        return

    # 1. DATA INGESTION & CLEANING 
    df = processor.load_and_clean_data(file_name)
    X = df.drop(['hash', 'malware'], axis=1, errors='ignore')
    y = df['malware']

    # 2. FEATURE EXTRACTION (Requirement F3)
    print("Isolating critical API sequences (t_1, t_2 & Red Flags)...")
    X_refined = extractor.isolate_api_sequences(X)

    # 3. NORMALIZATION 
    X_normalized = processor.apply_normalization(X_refined)
    print("SUCCESS: Data normalized and ready for the Intelligence Layer.")

    # 4. DATA BALANCING (Addressing the 0.51 recall issue via SMOTE) 
    X_balanced, y_balanced = processor.balance_data(X_normalized, y)

    # 5. SPLIT & TRAIN
    X_train, X_test, y_train, y_test = train_test_split(X_balanced, y_balanced, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 6. RESULTS OUTPUT 
    predictions = model.predict(X_test)
    print("\n--- Nebula Detection Performance ---")
    print(classification_report(y_test, predictions))

    # 7. FEATURE IMPORTANCE CHART
    importances = model.feature_importances_
    # Safeguard in case we isolated fewer than 10 features
    num_features = min(10, len(X_balanced.columns))
    indices = np.argsort(importances)[-num_features:] 

    plt.figure(figsize=(10,6))
    plt.title(f'Nebula Engine: Top {num_features} Behavioral Features')
    plt.barh(range(len(indices)), importances[indices], color='teal', align='center')
    plt.yticks(range(len(indices)), [X_balanced.columns[i] for i in indices])
    plt.xlabel('Relative Importance')
    plt.tight_layout()
    plt.savefig('nebula_feature_importance.png', dpi=300)
    print("\nVisual: Feature importance chart saved as 'nebula_feature_importance.png'")

    # 8. PERSISTENCE 
    joblib.dump(model, MODEL_FILE)
    print(f"Model saved successfully as '{MODEL_FILE}'")


def run_nebula_pipeline(file_path):
    """
    DETECTION PHASE: Predicts malware and provides Human-Readable Local XAI.
    """
    df = pd.read_csv(file_path)
    X_new = df.drop(['hash', 'malware'], axis=1, errors='ignore')

    extractor = MalwareFeatureExtractor()
    refined_features = extractor.isolate_api_sequences(X_new)
    
    try:
        model = joblib.load(MODEL_FILE) 
    except FileNotFoundError:
        raise Exception(f"Model file '{MODEL_FILE}' not found! Train the model first.")

    refined_features = refined_features.reindex(columns=model.feature_names_in_, fill_value=0)

    prediction = model.predict(refined_features)
    probabilities = model.predict_proba(refined_features)
    
    confidence = max(probabilities[0]) * 100 
    verdict = "Malicious" if prediction[0] == 1 else "Benign"
    
    # --- UPDATED LOCAL XAI LOGIC (Human-Readable Translation) ---
    
    # Dictionary translating raw dataset columns into plain English for the Analyst
    feature_descriptions = {
        't_1': "Suspicious API calls clustered in the initial launch phase (0-2 seconds).",
        't_2': "Anomalous execution behavior during the secondary loading phase (2-5 seconds).",
        'RegSetValue': "Detected attempt to modify the Windows Registry (Likely Persistence).",
        'NtCreateProcess': "Detected attempt to spawn a hidden process (Likely Injection).",
        'ConnectEx': "Detected unprompted outbound network connection (Likely C2 Beaconing).",
        'NtWriteVirtualMemory': "Detected code injection into another running process.",
        'CreateRemoteThread': "Detected attempt to execute payload in a remote thread."
    }

    if verdict == "Malicious":
        # Find the specific feature that triggered the alarm
        top_feature = refined_features.iloc[0].idxmax()
        
        # Translate it using the dictionary. If it's a new API not in the list, just show the name.
        human_readable = feature_descriptions.get(top_feature, f"Anomalous usage of API: {top_feature}")
        reason = human_readable
    else:
        reason = "Normal execution flow. No red flags found."
        
    return verdict, confidence, reason


if __name__ == "__main__":
    # If you run `python main.py` directly, it will TRAIN the model.
    TEST_FILE = 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
    train_nebula_model(TEST_FILE)