import os
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE


# --- Configuration ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'data'
MODELS_DIR = PROJECT_ROOT / 'models'
MODEL_FILE = MODELS_DIR / 'behavioral_rf_model.pkl'
CHART_FILE = MODELS_DIR / 'behavioral_feature_importance.png'
DATASET_FILE = DATA_DIR / 'merged_training_data.csv'
MIN_NONZERO_API_CALLS = 5


def describe_api_call(api_name):
    api = api_name.lower()

    if api in {
        'createremotethread', 'createremotethreadex', 'ntcreatethreadex',
        'rtlcreateuserthread', 'ntqueueapcthread', 'ntsetcontextthread',
        'ntgetcontextthread', 'writeprocessmemory', 'readprocessmemory',
        'ntwritevirtualmemory', 'ntreadvirtualmemory'
    }:
        return 'Manipulates processes or threads; often used for injection or hijacking.'

    if api in {'openprocess', 'openthread', 'ntopenprocess', 'ntopenthread', 'ntduplicateobject'}:
        return 'Opens sensitive handles; malware uses it before tampering or injection.'

    if api in {'process32firstw', 'process32nextw', 'thread32first', 'thread32next', 'module32firstw', 'module32nextw', 'createtoolhelp32snapshot'}:
        return 'Enumerates processes or modules; malware uses it for victim reconnaissance.'

    if api.startswith('reg') or any(token in api for token in ('openkey', 'createkey', 'deletekey', 'deletevalue', 'setvalue', 'querykey', 'queryvalue', 'enumvalue', 'enumkey', 'loadkey', 'unloadkey')):
        if any(token in api for token in ('query', 'enum', 'close')):
            return 'Reads registry data; malware uses it to locate defenses or persistence.'
        return 'Modifies registry settings; malware uses it for persistence or evasion.'

    if api.startswith('internet') or api.startswith('http') or api in {
        'connect', 'socket', 'bind', 'listen', 'accept', 'send', 'recv', 'sendto',
        'recvfrom', 'shutdown', 'getsockname', 'setsockopt', 'ioctlsocket', 'wsastartup',
        'wsasocketa', 'wsasocketw', 'wsaconnect', 'wsasend', 'wsarecv', 'wsasendto',
        'wsarecvfrom', 'dnsquery_a', 'getaddrinfo', 'gethostbyname'
    }:
        return 'Opens network connections; malware uses it for command-and-control or exfiltration.'

    if 'service' in api or 'scmanager' in api:
        return 'Controls services; malware uses it for persistence and defense evasion.'

    if 'crypt' in api or api in {'decryptmessage', 'encryptmessage', 'protectmemory', 'unprotectmemory'}:
        return 'Encrypts or decrypts data; malware uses it for ransomware or concealment.'

    if api in {'isdebuggerpresent', 'setunhandledexceptionfilter', 'outputdebugstringa', 'outputdebugstringw', 'findwindowa', 'findwindoww', 'findwindowexa', 'findwindowexw'}:
        return 'Inspects debugging or window state; malware uses it to detect analysis.'

    if api in {'getasynckeystate', 'getkeyboardstate', 'getkeystate'}:
        return 'Reads input state; malware may use it for keylogging or surveillance.'

    if api in {'getsystemmetrics', 'getsysteminfo', 'getnativesysteminfo', 'getcomputernamea', 'getcomputernamew', 'getusernamea', 'getusernamew', 'getusernameexa', 'getusernameexw', 'globalmemorystatusex', 'globalmemorystatus', 'getdiskfreespacew', 'getdiskfreespaceexw', 'getdiskfreespaceex', 'getfileattributesw', 'getfileattributesexw', 'getfileversioninfow', 'getfileversioninfosizew', 'getfileversioninfoexw', 'getfileinformationbyhandle', 'getfileinformationbyhandleex', 'getfiletype', 'getvolumenameforvolumemountpointw', 'getvolumepathnamew', 'getvolumepathnamesforvolumenamew', 'gettimezoneinformation', 'getadaptersinfo', 'getadaptersaddresses', 'netusergetinfo', 'netusergetlocalgroups', 'netgetjoininformation', 'getbestinterfaceex'}:
        return 'Queries system details; malware uses it to profile victims before acting.'

    if api in {'copyfilea', 'copyfilew', 'copyfileexw', 'movefilewithprogressw', 'deletefilew', 'removedirectorya', 'removedirectoryw', 'createdirectoryw', 'createdirectoryexw', 'setfileinformationbyhandle', 'setfilepointer', 'setfilepointerex', 'setfiletime', 'setendoffile', 'ntopenfile', 'ntcreatefile', 'ntreadfile', 'ntwritefile', 'ntdeletefile', 'ntsetinformationfile', 'ntqueryinformationfile', 'ntqueryattributesfile', 'ntqueryfullattributesfile', 'ntquerydirectoryfile', 'ntdeviceiocontrolfile', 'searchpathw', 'loadresource', 'sizeresource', 'findresourcea', 'findresourceexa', 'findresourceexw', 'findresourcew', 'readcabinetstate', 'getfilesize', 'getfilesizeex', 'getfileattributesexw', 'getshortpathnamew', 'gettemppathw', 'getfileinformationbyhandle', 'getfileinformationbyhandleex'}:
        return 'Reads or writes files; malware uses it to drop or hide payloads.'

    if api in {'coinitializeex', 'coinitializesecurity', 'couninitialize', 'cocreateinstance', 'cocreateinstanceex', 'cogetclassobject', 'oleinitialize', 'iwbemservices_execquery', 'iwbemservices_execmethod', 'shgetfolderpathw', 'shgetspecialfolderlocation', 'certopenstore', 'certopenssystemstorea', 'certopensystemstorew', 'certopensystemstorea', 'certcontrolstore', 'certcreatcertificatecontext'}:
        return 'Uses COM, WMI, or certificates; malware abuses it for automation or trust.'

    if api.startswith('nt'):
        return 'Uses low-level NT services; malware often abuses them to evade detections.'

    return f'Calls {api_name}; malware may abuse it for execution, persistence, or stealth.'


# --- MITRE ATT&CK® Enterprise Behavioral Taxonomy ---
MITRE_ATTACK_MAPPING = {
    'injection': {
        'id': 'T1055',
        'name': 'Process Injection',
        'tactic': 'Privilege Escalation / Defense Evasion',
        'severity': 'Critical',
        'color': '#EF4444',
        'apis': {
            'createremotethread', 'createremotethreadex', 'ntcreatethreadex',
            'rtlcreateuserthread', 'ntqueueapcthread', 'ntsetcontextthread',
            'ntgetcontextthread', 'writeprocessmemory', 'readprocessmemory',
            'ntwritevirtualmemory', 'ntreadvirtualmemory', 'ntallocatevirtualmemory',
            'ntprotectvirtualmemory', 'virtualallocex', 'virtualprotectex'
        }
    },
    'process_access': {
        'id': 'T1057',
        'name': 'Process Discovery & Handle Tampering',
        'tactic': 'Discovery / Defense Evasion',
        'severity': 'High',
        'color': '#F97316',
        'apis': {
            'openprocess', 'openthread', 'ntopenprocess', 'ntopenthread', 'ntduplicateobject',
            'ntsuspendthread', 'ntresumethread', 'ntterminateprocess', 'createtoolhelp32snapshot',
            'process32firstw', 'process32nextw', 'thread32first', 'thread32next',
            'module32firstw', 'module32nextw'
        }
    },
    'registry_persistence': {
        'id': 'T1547.001',
        'name': 'Registry Run Keys / Startup Folder',
        'tactic': 'Persistence / Privilege Escalation',
        'severity': 'High',
        'color': '#F97316',
        'apis': {
            'regsetvalueexw', 'regsetvalueexa', 'regcreatekeyexw', 'regcreatekeyexa',
            'regdeletevaluew', 'regdeletevaluea', 'regdeletekeyw', 'regdeletekeya',
            'ntsetvaluekey', 'ntcreatekey', 'ntdeletekey', 'ntdeletevaluekey'
        }
    },
    'registry_discovery': {
        'id': 'T1012',
        'name': 'Query Registry',
        'tactic': 'Discovery',
        'severity': 'Medium',
        'color': '#F59E0B',
        'apis': {
            'regqueryvalueexw', 'regqueryvalueexa', 'regqueryinfokeyw', 'regqueryinfokeya',
            'regopenkeyexw', 'regopenkeyexa', 'regenumkeyw', 'regenumkeyexw', 'regenumkeyexa',
            'regenumvaluew', 'regenumvaluea', 'ntopenkey', 'ntopenkeyex', 'ntqueryvaluekey', 'ntquerykey'
        }
    },
    'network_c2': {
        'id': 'T1071.001',
        'name': 'Web Protocols (Command & Control)',
        'tactic': 'Command and Control',
        'severity': 'High',
        'color': '#F97316',
        'apis': {
            'connect', 'socket', 'bind', 'listen', 'accept', 'send', 'recv', 'sendto', 'recvfrom',
            'internetopenw', 'internetopena', 'internetopenurlw', 'internetopenurla',
            'internetconnectw', 'internetconnecta', 'httpopenrequestw', 'httpopenrequesta',
            'httpsendrequestw', 'httpsendrequesta', 'wsastartup', 'wsasocketa', 'wsasocketw',
            'wsaconnect', 'wsasend', 'wsarecv', 'wsasendto', 'wsarecvfrom', 'dnsquery_a',
            'getaddrinfo', 'getaddrinfow', 'gethostbyname', 'urldownloadtofilew',
            'internetreadfile', 'internetwritefile'
        }
    },
    'defense_evasion': {
        'id': 'T1497.001',
        'name': 'Virtualization/Sandbox Evasion: System Checks',
        'tactic': 'Defense Evasion',
        'severity': 'High',
        'color': '#F97316',
        'apis': {
            'isdebuggerpresent', 'setunhandledexceptionfilter', 'outputdebugstringa', 'outputdebugstringw',
            'findwindowa', 'findwindoww', 'findwindowexa', 'findwindowexw', 'ntdelayexecution',
            'rtladdvectoredexceptionhandler', 'rtlremovevectoredexceptionhandler'
        }
    },
    'credential_access': {
        'id': 'T1056.001',
        'name': 'Input Capture: Keylogging & Credentials',
        'tactic': 'Credential Access',
        'severity': 'Critical',
        'color': '#EF4444',
        'apis': {
            'getasynckeystate', 'getkeyboardstate', 'getkeystate', 'registerhotkey',
            'cryptunprotectdata', 'cryptunprotectmemory'
        }
    },
    'encryption_impact': {
        'id': 'T1486',
        'name': 'Data Encrypted for Impact (Ransomware Behavior)',
        'tactic': 'Impact',
        'severity': 'High',
        'color': '#F97316',
        'apis': {
            'cryptencrypt', 'cryptdecrypt', 'cryptgenkey', 'cryptexportkey',
            'cryptacquirecontextw', 'cryptacquirecontexta', 'cryptprotectdata', 'cryptprotectmemory'
        }
    },
    'service_tampering': {
        'id': 'T1543.003',
        'name': 'Windows Service Execution & Manipulation',
        'tactic': 'Persistence / Privilege Escalation',
        'severity': 'Critical',
        'color': '#EF4444',
        'apis': {
            'createservicew', 'createservicea', 'startservicew', 'startservicea',
            'openscmanagerw', 'openscmanagera', 'openservicew', 'openservicea',
            'controlservice', 'deleteservice'
        }
    },
    'file_staging': {
        'id': 'T1105',
        'name': 'Ingress Tool Transfer & File Manipulation',
        'tactic': 'Command and Control / Execution',
        'severity': 'Medium',
        'color': '#F59E0B',
        'apis': {
            'copyfilea', 'copyfilew', 'copyfileexw', 'movefilewithprogressw',
            'deletefilew', 'ntdeletefile', 'ntwritefile', 'ntcreatefile',
            'gettemppathw', 'createdirectoryw', 'createdirectoryexw'
        }
    },
    'system_recon': {
        'id': 'T1082',
        'name': 'System Information Discovery & Profiling',
        'tactic': 'Discovery',
        'severity': 'Low',
        'color': '#38BDF8',
        'apis': {
            'getsystemmetrics', 'getsysteminfo', 'getnativesysteminfo', 'getcomputernamea',
            'getcomputernamew', 'getusernamea', 'getusernamew', 'globalmemorystatusex',
            'getadaptersinfo', 'getadaptersaddresses', 'netusergetinfo'
        }
    }
}


def map_api_to_mitre(api_name):
    """Maps an API call name to its matching MITRE ATT&CK technique details, or None."""
    if not api_name:
        return None
    clean = api_name.lower().split('.')[-1]
    for key, data in MITRE_ATTACK_MAPPING.items():
        if clean in data['apis']:
            return {
                'category_key': key,
                'id': data['id'],
                'name': data['name'],
                'tactic': data['tactic'],
                'severity': data['severity'],
                'color': data['color'],
                'api': api_name,
            }
    return None


def calculate_threat_score(malware_probability, detected_techniques):
    """
    Computes a composite Threat Severity Score (0 - 100) from ML model confidence
    and active MITRE ATT&CK behavioral indicators.
    """
    base_score = float(malware_probability * 100.0)

    critical_count = sum(1 for t in detected_techniques if t.get('severity') == 'Critical')
    high_count = sum(1 for t in detected_techniques if t.get('severity') == 'High')
    medium_count = sum(1 for t in detected_techniques if t.get('severity') == 'Medium')

    modifier = (critical_count * 8.0) + (high_count * 4.0) + (medium_count * 1.5)

    if malware_probability >= 0.5:
        composite_score = min(100.0, max(base_score, base_score * 0.7 + modifier + 20.0))
    else:
        if critical_count > 0:
            composite_score = min(75.0, base_score + (critical_count * 16.0))
        elif high_count > 1:
            composite_score = min(55.0, base_score + (high_count * 8.0))
        else:
            composite_score = max(0.0, base_score)

    composite_score = round(composite_score, 1)

    if composite_score >= 80:
        severity = "CRITICAL"
        color = "#EF4444"
    elif composite_score >= 60:
        severity = "HIGH"
        color = "#F97316"
    elif composite_score >= 40:
        severity = "MEDIUM"
        color = "#F59E0B"
    elif composite_score >= 20:
        severity = "LOW"
        color = "#38BDF8"
    else:
        severity = "CLEAN / BENIGN"
        color = "#10B981"

    return composite_score, severity, color


class DetectionReport(dict):
    """Report dictionary subclass that unpacks as (verdict, confidence, reason) for legacy compatibility."""
    def __iter__(self):
        yield self["verdict"]
        yield self["confidence"]
        yield self["reason"]



def _api_name_from_encoded_value(value):
    """Map a numeric API sequence value back to the API name used by json_parser."""
    try:
        api_index = int(round(float(value)))
    except (TypeError, ValueError):
        return None

    # In this dataset, 0 is also used for padding. Avoid explaining padding as an API.
    if api_index == 0:
        return None

    try:
        from .json_parser import API_MAPPING_DICT
    except ImportError:
        from json_parser import API_MAPPING_DICT

    api_index_to_name = {index: api_name for api_name, index in API_MAPPING_DICT.items()}
    return api_index_to_name.get(api_index)


def _describe_engineered_feature(feature_name, value):
    explanations = {
        'sequence_sum': 'Overall encoded API activity level in the sequence.',
        'sequence_mean': 'Average encoded API value across the sequence.',
        'sequence_std': 'Variation in API values across the sequence.',
        'sequence_min': 'Lowest encoded API value observed in the sequence.',
        'sequence_max': 'Highest encoded API value observed in the sequence.',
        'sequence_unique_count': 'Number of distinct API values observed in the sequence.',
        'sequence_repeat_rate': 'How often API values repeat across the sequence.',
        'sequence_entropy': 'Diversity and unpredictability of the API sequence.',
        'sequence_change_count': 'Number of changes between adjacent API sequence positions.',
    }
    explanation = explanations.get(feature_name, f'Model feature {feature_name}.')
    return f'{feature_name}={float(value):.3f}. {explanation}'


def explain_local_indicator(X_new, pipeline):
    """
    Build a sample-specific explanation from the trained model's strongest
    sequence positions and the actual API values in the uploaded sample.
    """
    clf = pipeline.named_steps.get('clf') if hasattr(pipeline, 'named_steps') else None
    if clf is None or not hasattr(clf, 'feature_importances_'):
        return 'Malicious behavior detected by the Support Vector Machine.'

    row = X_new.iloc[0]
    importances = pd.Series(clf.feature_importances_, index=X_new.columns)
    ranked_features = importances.sort_values(ascending=False).index

    for feature_name in ranked_features:
        if not (feature_name.startswith('t_') and feature_name[2:].isdigit()):
            continue

        api_name = _api_name_from_encoded_value(row.get(feature_name))
        if api_name:
            return (
                f'{feature_name} contains {api_name}. '
                f'{describe_api_call(api_name)}'
            )

    top_feature = ranked_features[0]
    return _describe_engineered_feature(top_feature, row.get(top_feature, 0))


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


def _sequence_columns(columns):
    return [column for column in columns if column.startswith('t_') and column[2:].isdigit()]


def _validate_behavioral_input(X_raw, expected_columns, is_json_input):
    """
    Validate raw behavioral sequence input before engineered features and model inference.
    This prevents unrelated or empty files from being converted into all-zero model input.
    """
    if X_raw.empty:
        raise ValueError('Input file is empty. Please provide a behavioral CSV or JSON sample.')

    sequence_columns = _sequence_columns(X_raw.columns)
    if not sequence_columns:
        raise ValueError(
            'Input file is invalid. Expected behavioral sequence columns such as t_0, t_1, ..., t_99.'
        )

    expected_sequence_columns = _sequence_columns(expected_columns)
    missing_sequence_columns = [
        column for column in expected_sequence_columns if column not in X_raw.columns
    ]
    if missing_sequence_columns:
        preview = ', '.join(missing_sequence_columns[:5])
        suffix = '...' if len(missing_sequence_columns) > 5 else ''
        raise ValueError(
            f'Input file is missing required behavioral sequence columns: {preview}{suffix}'
        )

    sequence_frame = X_raw[expected_sequence_columns].apply(pd.to_numeric, errors='coerce').fillna(0)
    non_zero_api_calls = int((sequence_frame.iloc[0] != 0).sum())

    if non_zero_api_calls < MIN_NONZERO_API_CALLS:
        if is_json_input:
            raise ValueError(
                'Input JSON contains no usable API behavior. '
                f'At least {MIN_NONZERO_API_CALLS} recognized non-zero API calls are required.'
            )
        raise ValueError(
            'Input file contains no usable API behavior. '
            f'At least {MIN_NONZERO_API_CALLS} non-zero API calls are required.'
        )

def train_detection_model(data_path):
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

    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced_subsample',
    )
    
    svm_model = CalibratedClassifierCV(
        LinearSVC(max_iter=10000, class_weight='balanced', random_state=42)
    )

    # Build an imbalanced-learn pipeline that applies SMOTE only during training
    smote = SMOTE(random_state=42)
    rf_pipeline = ImbPipeline([('smote', SMOTE(random_state=42)), ('clf', rf_model)])
    svm_pipeline = ImbPipeline([('smote', SMOTE(random_state=42)), ('scaler', StandardScaler()), ('clf', svm_model)])

    # Cross-validation is run only on the training split; SMOTE will be applied inside each fold
    print("\n[SCIENTIFIC VALIDATION] Starting 5-Fold Cross-Validation on training data with SMOTE in-fold...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    rf_scores = cross_val_score(rf_pipeline, X_train, y_train, cv=cv, scoring='balanced_accuracy')
    svm_scores = cross_val_score(svm_pipeline, X_train, y_train, cv=cv, scoring='balanced_accuracy')

    rf_mean_acc = np.mean(rf_scores)
    svm_mean_acc = np.mean(svm_scores)

    print("=" * 60)
    print("CROSS-VALIDATION RESULTS (K=5) - Balanced Accuracy")
    print(f"Random Forest : Mean: {rf_mean_acc * 100:.2f}% | Std: {np.std(rf_scores) * 100:.2f}%")
    print(f"SVM           : Mean: {svm_mean_acc * 100:.2f}% | Std: {np.std(svm_scores) * 100:.2f}%")
    print("=" * 60)

    print("\nTraining final production models on the full training split (SMOTE applied during fit)...")
    rf_pipeline.fit(X_train, y_train)
    svm_pipeline.fit(X_train, y_train)

    rf_test_predictions = rf_pipeline.predict(X_test)
    svm_test_predictions = svm_pipeline.predict(X_test)
    
    print("\n--- Behavioral Detection Performance on Held-Out Test Set ---")
    print("[Random Forest Classification Report]")
    print(classification_report(y_test, rf_test_predictions))
    print("\n[SVM Classification Report]")
    print(classification_report(y_test, svm_test_predictions))

    if rf_mean_acc >= svm_mean_acc:
        print("\n=> Random Forest performed best. Saving Random Forest model...")
        best_pipeline = rf_pipeline
    else:
        print("\n=> SVM performed best. Saving SVM model...")
        best_pipeline = svm_pipeline

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    temp_model_file = MODEL_FILE.with_suffix(MODEL_FILE.suffix + '.tmp')
    temp_chart_file = CHART_FILE.with_suffix(CHART_FILE.suffix + '.tmp')
    chart_created = False

    # Extract feature importances only if the best model supports it
    clf = best_pipeline.named_steps['clf']
    if hasattr(clf, 'feature_importances_'):
        importances = clf.feature_importances_
        feature_names = X_train.columns
        feature_importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
        feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False).head(10)

        # For malware samples, find the most common API value at each top t_N position,
        # then decode the numeric index to a human-readable API name using the existing helper.
        malware_rows = df[df['malware'] == 1]

        def decode_feature_label(col_name):
            """Return 'APIName (t_N)' for t_N columns, or col_name as-is for engineered features."""
            if col_name.startswith('t_') and col_name[2:].isdigit() and col_name in malware_rows.columns:
                most_common_val = malware_rows[col_name].mode()
                if not most_common_val.empty:
                    api_name = _api_name_from_encoded_value(most_common_val.iloc[0])
                    if api_name:
                        return f'{api_name} ({col_name})'
            return col_name

        feature_importance_df['Label'] = feature_importance_df['Feature'].apply(decode_feature_label)

        plt.figure(figsize=(12, 6))
        plt.barh(feature_importance_df['Label'], feature_importance_df['Importance'], color='#008080')
        plt.xlabel('Importance Score')
        plt.ylabel('Most Common API Call at Position')
        plt.title('Top 10 Most Influential API Calls (Global XAI)')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(temp_chart_file, format='png')
        plt.close()
        chart_created = True
        print(f"Global XAI chart staged as '{temp_chart_file}'")

    joblib.dump(
        {
            'pipeline': best_pipeline,
            'feature_names': list(X_train.columns),
        },
        temp_model_file,
    )

    if chart_created:
        os.replace(temp_chart_file, CHART_FILE)
        print(f"Global XAI chart saved as '{CHART_FILE}'")
    os.replace(temp_model_file, MODEL_FILE)

    print(f"Best model saved as '{MODEL_FILE}'")

def extract_sample_behaviors(X_row):
    """
    Extracts ordered non-zero API calls from the sample, maps them to MITRE ATT&CK,
    and returns timeline events and deduplicated MITRE techniques.
    """
    api_timeline = []
    seen_mitre_ids = set()
    detected_techniques = []

    sequence_cols = [c for c in X_row.columns if c.startswith('t_') and c[2:].isdigit()]
    sequence_cols = sorted(sequence_cols, key=lambda c: int(c[2:]))

    for col in sequence_cols:
        val = X_row[col].iloc[0]
        api_name = _api_name_from_encoded_value(val)
        if not api_name:
            continue

        mitre_info = map_api_to_mitre(api_name)
        event = {
            'step': col,
            'api': api_name,
            'description': describe_api_call(api_name),
            'mitre': mitre_info,
        }
        api_timeline.append(event)

        if mitre_info:
            tech_id = mitre_info['id']
            if tech_id not in seen_mitre_ids:
                seen_mitre_ids.add(tech_id)
                detected_techniques.append(mitre_info)

    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    detected_techniques.sort(key=lambda t: severity_order.get(t.get('severity', 'Low'), 4))

    return api_timeline, detected_techniques


def run_detection_pipeline(file_path):
    """
    DETECTION PHASE: Analyzes behavioral samples with ML inference,
    local explainability, MITRE ATT&CK mapping, and 0-100 threat severity scoring.
    """
    try:
        from .json_parser import flatten_speakeasy_json
    except ImportError:
        from json_parser import flatten_speakeasy_json
    
    is_json_input = file_path.lower().endswith('.json')

    if is_json_input:
        df = flatten_speakeasy_json(file_path)
    else:
        df = pd.read_csv(file_path)
        if len(df) > 1:
            print(f"Warning: {len(df)} rows detected, analyzing first sample only.")

    X_new = df.drop(['hash', 'malware'], axis=1, errors='ignore')

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

    _validate_behavioral_input(X_new, expected_columns, is_json_input)
    X_new = engineer_sequence_features(X_new)
    X_new = X_new.reindex(columns=expected_columns, fill_value=0)
    X_new = X_new.head(1)

    prediction = pipeline.predict(X_new)
    probabilities = pipeline.predict_proba(X_new)

    classes = list(getattr(pipeline, 'classes_', [0, 1]))
    malware_idx = classes.index(1) if 1 in classes else 1
    malware_prob = float(probabilities[0][malware_idx]) if len(probabilities[0]) > malware_idx else float(prediction[0])

    confidence = float(max(probabilities[0]) * 100)
    verdict = "Malicious" if prediction[0] == 1 else "Benign"

    api_timeline, detected_techniques = extract_sample_behaviors(X_new)
    threat_score, severity, severity_color = calculate_threat_score(malware_prob, detected_techniques)

    if verdict == "Malicious":
        reason = explain_local_indicator(X_new, pipeline)
    else:
        if detected_techniques:
            reason = f"Normal execution flow overall ({confidence:.1f}% benign confidence), with {len(detected_techniques)} monitored API pattern(s)."
        else:
            reason = "Normal execution flow. No red flags found."

    report = DetectionReport({
        "verdict": verdict,
        "confidence": confidence,
        "threat_score": threat_score,
        "severity": severity,
        "severity_color": severity_color,
        "reason": reason,
        "malware_probability": malware_prob,
        "mitre_techniques": detected_techniques,
        "api_timeline": api_timeline,
        "total_api_calls": len(api_timeline),
        "unique_api_count": len(set(e['api'] for e in api_timeline)),
    })
    return report

if __name__ == "__main__":
    # Running this script directly starts the comprehensive training & validation process
    train_detection_model(DATASET_FILE)
