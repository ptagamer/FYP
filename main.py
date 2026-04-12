import os
import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Import the modular logic from new file
from processors import BehavioralDataProcessor

# The "Golden Hash" for Appendix D 
EXPECTED_HASH = "11005ff6f5007bfee7d60bd0dc2e787f4e77b46f3b0a3d09424421c5339a8406"

def run_nebula_pipeline():
    """
    Acts as the Task Controller to coordinate data ingestion, 
    integrity verification, and model training[cite: 465, 646].
    """
    file_name = 'dynamic_api_call_sequence_per_malware_100_0_306.csv'
    
    # 1. INITIALIZE DATA LAYER
    processor = BehavioralDataProcessor(expected_hash=EXPECTED_HASH)
    
    # 2. ACTIVE INTEGRITY CHECK (Safety Constraint)
    if not os.path.exists(file_name):
        print(f"ERROR: Dataset {file_name} not found.")
        return

    try:
        processor.verify_integrity(file_name)
    except ValueError as e:
        print(f"CRITICAL ERROR: {e}")
        return

    # 3. DATA INGESTION & CLEANING (Requirement F2) 
    df = processor.load_and_clean_data(file_name)
    X = df.drop(['hash', 'malware'], axis=1)
    y = df['malware']

    # 4. NORMALIZATION (F2 Scaling) 
    X_normalized = processor.apply_normalization(X)
    print("SUCCESS: Data normalized and ready for the Intelligence Layer.")

    # 5. DATA BALANCING (Addressing Class Imbalance) 
    # This addresses the 0.51 recall issue found in Section 6.3 
    X_balanced, y_balanced = processor.balance_data(X_normalized, y)

    # 6. UPDATED SPLIT (Using Balanced Data)
    X_train, X_test, y_train, y_test = train_test_split(X_balanced, y_balanced, test_size=0.2, random_state=42)

    # 7. MODEL TRAINING (Requirement F4) 
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 8. RESULTS OUTPUT (Evaluation Phase) 
    predictions = model.predict(X_test)
    print("\n--- Nebula Detection Performance ---")
    print(classification_report(y_test, predictions))

    # 9. FEATURE IMPORTANCE (Presentation Layer)
    # Identifying critical API sequences at t_1 and t_2
    importances = model.feature_importances_
    indices = np.argsort(importances)[-10:] 

    plt.figure(figsize=(10,6))
    plt.title('Nebula Engine: Top 10 Behavioral Features (API Sequences)')
    plt.barh(range(len(indices)), importances[indices], color='teal', align='center')
    plt.yticks(range(len(indices)), [X_balanced.columns[i] for i in indices])
    plt.xlabel('Relative Importance')
    plt.tight_layout()
    
    plt.savefig('nebula_feature_importance.png', dpi=300)
    print("\nVisual: Feature importance chart saved as 'nebula_feature_importance.png'")
    # Note: show() is for debugging; final GUI will use the saved .png 
    plt.show()

    # 10. PERSISTENCE (Data Layer) 
    # Saving the model for future GUI integration 
    joblib.dump(model, 'nebula_rf_model.pkl')
    print("\nModel saved successfully as 'nebula_rf_model.pkl'")

if __name__ == "__main__":
    run_nebula_pipeline()

    # Final Verification check
    if os.path.exists('nebula_rf_model.pkl'):
        print("\nSUCCESS: Serialized model 'nebula_rf_model.pkl' found and verified.")
        loaded_model = joblib.load('nebula_rf_model.pkl')
        print("SUCCESS: Intelligence Layer reloaded into memory perfectly.")
    else:
        print("\nERROR: Model file missing. Check folder permissions.")