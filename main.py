import os

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

# --- Configuration ---
MODEL_FILE = 'nebula_rf_model.pkl'
# This is your original training dataset
DATASET_FILE = 'dynamic_api_call_sequence_per_malware_100_0_306.csv' 


FEATURE_DESCRIPTIONS = {
    't_0': "Suspicious activity detected at the entry point.",
    't_1': "Suspicious API calls clustered in the initial launch phase.",
    't_2': "Anomalous execution behavior during the secondary loading phase.",
}


def engineer_sequence_features(df):
    """Create compact behavioral summaries from the raw API sequence columns."""
    sequence_columns = [column for column in df.columns if column.startswith('t_') and column[2:].isdigit()]

    if not sequence_columns:
        return df.copy()

    sequence_frame = df[sequence_columns].apply(pd.to_numeric, errors='coerce')
    engineered = df.copy()

    engineered['sequence_sum'] = sequence_frame.sum(axis=1)
    engineered['sequence_mean'] = sequence_frame.mean(axis=1)
    engineered['sequence_std'] = sequence_frame.std(axis=1).fillna(0)
    engineered['sequence_min'] = sequence_frame.min(axis=1)
    engineered['sequence_max'] = sequence_frame.max(axis=1)
    engineered['sequence_unique_count'] = sequence_frame.nunique(axis=1)
    engineered['sequence_repeat_rate'] = 1 - (engineered['sequence_unique_count'] / len(sequence_columns))

    def row_entropy(row):
        counts = row.value_counts(dropna=True)
        probabilities = counts / counts.sum()
        return float(-(probabilities * np.log2(probabilities)).sum()) if not probabilities.empty else 0.0

    engineered['sequence_entropy'] = sequence_frame.apply(row_entropy, axis=1)
    engineered['sequence_change_count'] = sequence_frame.diff(axis=1).fillna(0).ne(0).sum(axis=1)

    return engineered


def _class_distribution(values):
    unique, counts = np.unique(values, return_counts=True)
    return dict(zip(unique.tolist(), counts.tolist()))

def train_nebula_model(data_path):
    """
    TRAINING PHASE: Splits off an untouched test set, performs cross-validation
    on the training data, applies SMOTE inside each fold, and saves the model
    together with the feature layout used during training.
    """
    if not os.path.exists(data_path):
        print(f"Error: Dataset {data_path} not found!")
        return

    print(f"--- Loading Dataset for Training: {data_path} ---")
    df = pd.read_csv(data_path)

    if 'malware' not in df.columns:
        raise ValueError("Dataset must contain a 'malware' target column.")

    # Features (X) and Target (y)
    X = df.drop(['hash', 'malware'], axis=1, errors='ignore')
    y = df['malware']

    X = engineer_sequence_features(X)

    X = X.apply(pd.to_numeric, errors='raise')
    y = y.astype(int)

    print(f"\n[DATA ENGINEERING] Full dataset distribution: {_class_distribution(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print(f"[DATA ENGINEERING] Training split distribution: {_class_distribution(y_train)}")
    print(f"[DATA ENGINEERING] Test split distribution: {_class_distribution(y_test)}")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced_subsample',
    )

    # Cross-validation is run only on the training split, with class weighting
    # to reduce bias toward the dominant malware class.
    print("\n[SCIENTIFIC VALIDATION] Starting 5-Fold Cross-Validation on training data...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='balanced_accuracy')

    print("=" * 45)
    print("CROSS-VALIDATION RESULTS (K=5)")
    print(f"Mean Balanced Accuracy: {np.mean(scores) * 100:.2f}%")
    print(f"Standard Deviation: {np.std(scores) * 100:.2f}%")
    print("=" * 45)

    print("\nTraining final production model on the full training split...")
    model.fit(X_train, y_train)

    test_predictions = model.predict(X_test)
    print("\n--- Nebula Detection Performance on Held-Out Test Set ---")
    print(classification_report(y_test, test_predictions))

    importances = model.feature_importances_
    feature_names = X_train.columns
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

    joblib.dump(
        {
            'pipeline': model,
            'feature_names': list(X_train.columns),
        },
        MODEL_FILE,
    )

    print(f"Model saved as '{MODEL_FILE}'")
    print("Global XAI chart saved as 'nebula_feature_importance.png'")

def run_nebula_pipeline(file_path):
    """
    DETECTION PHASE: Used by gui.py to analyze files with Human-Readable Local XAI.
    """
    df = pd.read_csv(file_path)

    # Ensure we don't try to drop columns that aren't there.
    X_new = df.drop(['hash', 'malware'], axis=1, errors='ignore')
    X_new = engineer_sequence_features(X_new)

    try:
        loaded_model = joblib.load(MODEL_FILE)
    except FileNotFoundError:
        raise Exception("Model file missing. Please run main.py to train first.")

    if isinstance(loaded_model, dict) and 'pipeline' in loaded_model:
        pipeline = loaded_model['pipeline']
        expected_columns = loaded_model.get('feature_names', list(X_new.columns))
    else:
        pipeline = loaded_model
        expected_columns = list(getattr(pipeline, 'feature_names_in_', X_new.columns))

    X_new = X_new.reindex(columns=expected_columns, fill_value=0)

    prediction = pipeline.predict(X_new)
    probabilities = pipeline.predict_proba(X_new)
    
    confidence = max(probabilities[0]) * 100 
    verdict = "Malicious" if prediction[0] == 1 else "Benign"

    if verdict == "Malicious":
        # Identify the column that influenced the decision most for this specific row
        top_feature = X_new.iloc[0].idxmax()
        reason = FEATURE_DESCRIPTIONS.get(top_feature, f"High-risk behavioral pattern at: {top_feature}")
    else:
        reason = "Normal execution flow. No red flags found."
        
    return verdict, confidence, reason

if __name__ == "__main__":
    # Running this script directly starts the comprehensive training & validation process
    train_nebula_model(DATASET_FILE)