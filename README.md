# 🛡️ Behavioral Threat Defense Console

> **Machine Learning-Based Malware Detection via Dynamic API Sequence Ingestion & MITRE ATT&CK® Triage**

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/UI-CustomTkinter%206.0-0284C7.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20Imbalanced--Learn-F97316.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic%20FYP-green.svg)]()

---

## 📌 Overview

The **Behavioral Threat Defense Console** is an intelligent security operations center (SOC) application for detecting, triaging, and explaining malicious software based on **runtime behavioral execution traces**.

Rather than relying on fragile static signatures or file hashes, this system evaluates the **chronological sequence of Windows API calls** executed inside a sandbox environment (such as [Mandiant's Speakeasy](https://github.com/mandiant/speakeasy) emulator). It translates raw behavioral logs into fixed-dimensional sequence vectors, engineers behavioral entropy metrics, and performs inference using a class-balanced **Random Forest** and **Linear SVM** machine learning pipeline.

---

## ✨ Key Capabilities

* **🎨 Modern SOC Interface**: Built with `CustomTkinter` featuring a dark slate enterprise palette, responsive cards, and a unified single-window layout.
* **🎯 MITRE ATT&CK® Behavioral Mapping**: Automatically tags suspicious runtime API calls with enterprise ATT&CK technique IDs (e.g., `T1055` Process Injection, `T1547.001` Registry Run Keys, `T1071.001` Web C2).
* **📊 Composite Threat Severity Score (0–100)**: Combines machine learning probability with active ATT&CK severity modifiers to assign calibrated risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`).
* **⏱️ Interactive Runtime API Timeline**: Chronologically inspects every observed execution step (`t_0` through `t_99`) with functional descriptions and risk severity tags.
* **🧠 Explainable AI (XAI)**:
  * **Global XAI**: Evaluates feature importance across the dataset to highlight globally influential API positions and sequence metrics.
  * **Local XAI**: Explains specifically *why* a particular sample was flagged (e.g. process injection, sandbox evasion, registry tampering).
* **🔐 Role-Based Access Control (RBAC) & Audit Trail**: SQLite-backed authentication supporting **Analyst** and **Admin** roles with immutable cryptographic audit logging (`behavioral_security.db`).
* **🚀 1-Click Windows Launcher**: Launch the entire application with a single click via `Run_App.bat`.

---

## 🔬 System Architecture & Detection Pipeline

```
┌─────────────────────────────────┐
│  Speakeasy Sandbox Report / CSV │  (Raw Behavioral Log)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     JSON Ingestion & Parser     │  (Normalizes API names, strips prefixes,
│       (app/json_parser.py)      │   resolves A/W variants -> 100-step vector)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│       Feature Engineering       │  (Calculates Sequence Entropy, Variance,
│         (app/main.py)           │   Repetition Rate, and Transition Counts)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   Class-Balanced ML Pipeline    │  (Stratified 5-Fold Cross Validation
│   (Random Forest & LinearSVC)   │   with In-Fold SMOTE Oversampling)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     ATT&CK® & Threat Engine     │  (0-100 Threat Score, MITRE Taxonomy,
│         (app/main.py)           │   and Plain-English Local XAI Reasoning)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│       SOC Analyst Console       │  (CustomTkinter Interactive Dashboard)
│         (app/gui.py)            │
└─────────────────────────────────┘
```

---

## 📁 Repository Structure

```text
├── app/
│   ├── __init__.py
│   ├── auth.py              # SQLite authentication & cryptographic audit logging
│   ├── gui.py               # Modern CustomTkinter SOC analysis console & views
│   ├── json_parser.py       # Speakeasy JSON log parser & sequence encoder
│   ├── main.py              # ML training, cross-validation, MITRE engine, & XAI
│   └── processors.py        # Data verification & preprocessing utilities
├── scripts/
│   ├── build_dataset.py     # Batch compiler converting Speakeasy JSON archives to CSV
│   ├── create_demo_files.py # Generates verified benign and malicious demo samples
│   └── merge_dataset.py     # Dataset consolidation and normalization utility
├── data/                    # Training datasets and demo test files (*.csv)
├── models/                  # Serialized ML models (.pkl), training logs, & charts
├── Run_App.bat              # 1-Click double-clickable Windows launcher
├── gui.py                   # Root entry-point launcher
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* **Operating System**: Windows 10 / 11
* **Python**: Python 3.10 or higher installed

### 2. Installation
Clone this repository and set up a virtual environment:

```powershell
# Clone the repository
git clone https://github.com/ptagamer/FYP.git
cd FYP

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 3. Launching the Application
You can launch the dashboard using either of the following methods:

* **Option A (Recommended)**: Double-click **`Run_App.bat`** in File Explorer.
* **Option B**: Run via command-line:
  ```powershell
  .\.venv\Scripts\python.exe gui.py
  ```

---

## 🔑 Default Roles & Access Credentials

The application uses an SQLite database (`behavioral_security.db`) with PBKDF2-HMAC-SHA256 password hashing:

| Username | Default Password | Role | Permitted Actions |
|---|---|---|---|
| **`admin`** | *(Configured during setup)* | **Admin** | Full access: Behavioral Analysis, Model Retraining, Audit Logs, Analyst Management, Demo Generation |
| **`analyst1`** | *(Configured during setup)* | **Analyst** | Dedicated analysis access: Log Ingestion, MITRE Triage, and Execution Timelines |

*Admins can create, delete, and reset passwords for Analyst accounts directly inside the **Manage Analysts** tab.*

---

## 🧪 Training & Scientific Validation

To retrain the underlying machine learning models and generate updated evaluation metrics:

```powershell
.\.venv\Scripts\python.exe -m app.main
```

* **Dataset**: Dynamic Windows API sequence dataset with in-fold SMOTE oversampling.
* **Validation**: Stratified 5-Fold Cross-Validation evaluating Balanced Accuracy and Recall.
* **Output Artifacts**:
  * Serialized Model: `models/behavioral_rf_model.pkl`
  * Global XAI Feature Importance Chart: `models/behavioral_feature_importance.png`
  * Training Telemetry Log: `models/latest_training_report.txt`

---

## 🛡️ MITRE ATT&CK® Mapping Reference

The classification engine maps observed API sequences into enterprise ATT&CK techniques:

| Technique ID | Technique Name | Tactic | Exemplar Windows APIs |
|---|---|---|---|
| **T1055** | Process Injection | Privilege Escalation / Evasion | `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx` |
| **T1547.001** | Registry Run Keys / Startup | Persistence | `RegSetValueExW`, `RegCreateKeyExW`, `NtSetValueKey` |
| **T1071.001** | Web Protocols (C2) | Command and Control | `connect`, `InternetOpenUrlW`, `HttpSendRequestA`, `WSASend` |
| **T1497.001** | Sandbox / Debugger Evasion | Defense Evasion | `IsDebuggerPresent`, `SetUnhandledExceptionFilter`, `NtDelayExecution` |
| **T1056.001** | Keylogging & Input Capture | Credential Access | `GetAsyncKeyState`, `GetKeyboardState`, `RegisterHotKey` |
| **T1486** | Data Encrypted for Impact | Impact (Ransomware) | `CryptEncrypt`, `CryptDecrypt`, `CryptGenKey` |
| **T1543.003** | Windows Service Manipulation | Persistence / Escalation | `CreateServiceW`, `StartServiceW`, `OpenSCManagerW` |
| **T1082** | System Information Discovery | Discovery | `GetSystemMetrics`, `GetComputerNameW`, `GetAdaptersInfo` |
| **T1105** | Ingress Tool Transfer / File Staging | Execution / C2 | `CopyFileW`, `DeleteFileW`, `NtWriteFile`, `GetTempPathW` |

---

## 📜 License & Acknowledgments

This project is developed as an academic **Final Year Project (FYP)** focusing on behavioral malware analysis, dynamic API call sequence modeling, and explainable artificial intelligence (XAI).
