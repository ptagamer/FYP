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
    DETECTION PHASE: Called by gui.py to predict a new behavioral log.
    Fulfills Requirements F5 (Verdict) and F6 (Confidence Score).
    """
    # Add this line to see it in the terminal
    print(f"\n--- [GUI REQUEST] Analyzing: {file_path} ---") 
    
    df = pd.read_csv(file_path)
    X_new = df.drop(['hash', 'malware'], axis=1, errors='ignore')

    extractor = MalwareFeatureExtractor()
    refined_features = extractor.isolate_api_sequences(X_new)
    
    # Add this line to see feature isolation
    print(f"Isolated {len(refined_features.columns)} critical API features...") 

    # Load the trained model
    try:
        model = joblib.load(MODEL_FILE) 
    except FileNotFoundError:
        raise Exception(f"Model file '{MODEL_FILE}' not found! Please run main.py to train the model first.")

    # Safeguard: Align the columns so sklearn doesn't crash if the new file is missing a column
    refined_features = refined_features.reindex(columns=model.feature_names_in_, fill_value=0)

    prediction = model.predict(refined_features)
    probabilities = model.predict_proba(refined_features)
    
    confidence = max(probabilities[0]) * 100 
    verdict = "Malicious" if prediction[0] == 1 else "Benign"
    
    # Add this line to see the result in terminal too
    print(f"Result: {verdict} ({confidence:.2f}%)") 
    
    return verdict, confidence


if __name__ == "__main__":
    # If you run `python main.py` directly, it will TRAIN the model.
    TEST_FILE = 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
    train_nebula_model(TEST_FILE)