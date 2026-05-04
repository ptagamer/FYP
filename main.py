import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, KFold
from imblearn.over_sampling import SMOTE  # Essential for data balancing
import numpy as np
import matplotlib.pyplot as plt
import os
from processors import MalwareFeatureExtractor

# --- Configuration ---
MODEL_FILE = 'nebula_rf_model.pkl'
# This is your original training dataset
DATASET_FILE = 'dynamic_api_call_sequence_per_malware_100_0_306.csv' 

def train_nebula_model(data_path):
    """
    TRAINING PHASE: Balances data with SMOTE, performs K-Fold validation, 
    and saves the high-intelligence model with Global XAI.
    """
    if not os.path.exists(data_path):
        print(f"Error: Dataset {data_path} not found!")
        return

    print(f"--- Loading Dataset for Training: {data_path} ---")
    df = pd.read_csv(data_path)
    
    # Features (X) and Target (y)
    X = df.drop(['hash', 'malware'], axis=1, errors='ignore')
    y = df['malware']

    # 1. APPLY SMOTE (Balancing the classes)
    print(f"\n[DATA ENGINEERING] Original balance: {np.bincount(y)}")
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    print(f"[DATA ENGINEERING] Balanced with SMOTE: {np.bincount(y_resampled)}")

    # 2. INITIALIZE MODEL
    model = RandomForestClassifier(n_estimators=100, random_state=42)

    # 3. K-FOLD CROSS VALIDATION (Scientific Validation)
    print("\n[SCIENTIFIC VALIDATION] Starting 5-Fold Cross-Validation...")
    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    
    # We use the resampled data to ensure a fair test across both classes
    scores = cross_val_score(model, X_resampled, y_resampled, cv=kf)
    
    print("=" * 45)
    print(f"CROSS-VALIDATION RESULTS (K=5):")
    print(f"Mean Accuracy: {np.mean(scores)*100:.2f}%")
    print(f"Standard Deviation: {np.std(scores)*100:.2f}%")
    print("=" * 45)

    # 4. FINAL TRAINING & SAVE
    print("\nTraining final production model...")
    model.fit(X_resampled, y_resampled)
    joblib.dump(model, MODEL_FILE)
    
    # --- GLOBAL XAI: Save Feature Importance Chart ---
    importances = model.feature_importances_
    feature_names = X.columns
    feature_importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
    feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False).head(10)

    plt.figure(figsize=(10, 6))
    plt.barh(feature_importance_df['Feature'], feature_importance_df['Importance'], color='#008080')
    plt.xlabel('Importance Score')
    plt.ylabel('API Sequence Position')
    plt.title('Top 10 Behavioral Indicators (Global XAI)')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig('nebula_feature_importance.png')
    
    print(f"Model saved as '{MODEL_FILE}'")
    print("Global XAI chart saved as 'nebula_feature_importance.png'")

def run_nebula_pipeline(file_path):
    """
    DETECTION PHASE: Used by gui.py to analyze files with Human-Readable Local XAI.
    """
    df = pd.read_csv(file_path)
    # Ensure we don't try to drop columns that aren't there
    X_new = df.drop(['hash', 'malware'], axis=1, errors='ignore')

    extractor = MalwareFeatureExtractor()
    refined_features = extractor.isolate_api_sequences(X_new)
    
    try:
        model = joblib.load(MODEL_FILE) 
    except FileNotFoundError:
        raise Exception("Model file missing. Please run main.py to train first.")

    # Ensure columns match training data exactly
    refined_features = refined_features.reindex(columns=model.feature_names_in_, fill_value=0)

    prediction = model.predict(refined_features)
    probabilities = model.predict_proba(refined_features)
    
    confidence = max(probabilities[0]) * 100 
    verdict = "Malicious" if prediction[0] == 1 else "Benign"
    
    # --- LOCAL XAI: Human-Readable Translation ---
    feature_descriptions = {
        't_0': "Suspicious activity detected at the entry point.",
        't_1': "Suspicious API calls clustered in the initial launch phase.",
        't_2': "Anomalous execution behavior during the secondary loading phase.",
        'RegSetValue': "Attempt to modify Windows Registry (Likely Persistence).",
        'NtCreateProcess': "Attempt to spawn a hidden process (Likely Injection).",
        'ConnectEx': "Outbound network connection detected (Likely C2 Beaconing).",
        'NtWriteVirtualMemory': "Direct code injection into another running process.",
        'CreateRemoteThread': "Execution of payload in a remote thread."
    }

    if verdict == "Malicious":
        # Identify the column that influenced the decision most for this specific row
        top_feature = refined_features.iloc[0].idxmax()
        reason = feature_descriptions.get(top_feature, f"High-risk behavioral pattern at: {top_feature}")
    else:
        reason = "Normal execution flow. No red flags found."
        
    return verdict, confidence, reason

if __name__ == "__main__":
    # Running this script directly starts the comprehensive training & validation process
    train_nebula_model(DATASET_FILE)