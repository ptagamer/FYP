import pandas as pd
import hashlib
import os
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import SMOTE

"""
Legacy/supporting preprocessing module.

The current active training pipeline is implemented in app/main.py.
This module is retained for design traceability and earlier modular
data-processing experiments.
"""

class BehavioralDataProcessor:
    """
    Handles ingestion, integrity verification, and cleaning 
    of behavioral datasets as defined in the Data Layer.
    """
    def __init__(self, expected_hash):
        """
        Initializes the processor with the baseline 'Golden Hash'.
        """
        self.expected_hash = expected_hash
        self.scaler = MinMaxScaler()

    def verify_integrity(self, file_path):
        """
        Calculates and verifies SHA-256 hash to ensure forensic reliability.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        current_hash = sha256_hash.hexdigest()
        if current_hash != self.expected_hash:
            # Prevents analysis if data is tampered with 
            raise ValueError(f"Integrity check failed! Found: {current_hash}")
        
        print(f"SUCCESS: Data Integrity Verified.")
        return True

    def load_and_clean_data(self, file_path):
        """
        Loads dataset and removes null values per Requirement F2.
        """
        df = pd.read_csv(file_path)
        # Cleaning raw logs as specified in the functional requirements 
        df = df.dropna()
        return df

    def apply_normalization(self, X):
        """
        Applies Min-Max normalization to scale feature frequencies.
        """
        # Scaling is necessary for high-dimensional behavioral data 
        X_scaled = self.scaler.fit_transform(X)
        return pd.DataFrame(X_scaled, columns=X.columns)

    def balance_data(self, X, y):
        """
        Uses SMOTE to fix class imbalance and improve benign recall.
        """
        print("Applying SMOTE to balance classes...")
        # Generates synthetic benign samples to prevent detection disparity 
        smote = SMOTE(random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)
        
        # Display new distribution for documentation/audit purposes
        unique, counts = np.unique(y_resampled, return_counts=True)
        print(f"New Class Distribution: {dict(zip(unique, counts))}")
        
        return X_resampled, y_resampled


class MalwareFeatureExtractor:
    """
    Extracts and isolates specific behavioral features from the normalized data.
    Fulfills Requirement F3 and aligns with the system Class Diagram.
    """
    def __init__(self):
        # High-weight behavioral features (Red Flags) identified in literature
        self.critical_apis = [
            'RegSetValue', 'NtCreateProcess', 'ConnectEx', 
            'NtWriteVirtualMemory', 'CreateRemoteThread'
        ]

    def isolate_api_sequences(self, df):
        """
        Isolates early execution steps and critical API sequences.
        Prioritizes t_1 and t_2 as per Section 6.3 findings.
        """
        # 1. Prioritize early execution sequences (t_1, t_2)
        early_features = [col for col in df.columns if col in ['t_1', 't_2']]
        
        # 2. Isolate red flag APIs
        flagged_features = [col for col in df.columns if any(api in col for api in self.critical_apis)]
        
        # Combine, keeping only unique columns
        selected_columns = list(set(early_features + flagged_features))
        
        # Fallback safeguard: If the dataset doesn't contain these exact column names yet,
        # return the original dataframe to prevent the model from crashing.
        if not selected_columns:
            print("Warning: Specific Red Flags not found in dataset columns. Using baseline features.")
            return df
            
        return df[selected_columns]

    def identify_registry_modifications(self, df):
        """
        Specific method defined in the Class Diagram to identify persistence.
        """
        return [col for col in df.columns if 'Reg' in col]

    def map_process_spawning_events(self, df):
        """
        Specific method defined in the Class Diagram to identify code injection.
        """
        return [col for col in df.columns if 'Process' in col or 'Thread' in col]