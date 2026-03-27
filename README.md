# 🛡️ Y-SHIELD: Advanced PE Forensics & Heuristic Engine

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)

**Y-SHIELD** is a high-performance security research tool designed for **Static PE Analysis**. It bridges the gap between raw binary parsing and intuitive data visualization, providing researchers with the ability to detect packed executables and malicious indicators before execution.

---

## 🔬 Core Research Capabilities

### **1. High-Performance C Engine**
The heart of Y-SHIELD is a native Win64 DLL written in C, optimized for memory efficiency and raw speed.
* **PE Header Reconstruction:** Parses `IMAGE_DOS_HEADER` and `IMAGE_NT_HEADERS` directly from the binary stream.
* **Entropy Analysis:** Implements the **Shannon Entropy** algorithm to identify encrypted or packed sections (e.g., UPX, VMProtect).
* **IAT Mapping:** Extracts the **Import Address Table** to identify high-risk API combinations.

### **2. Heuristic Threat Scoring**
A weighted scoring system evaluates the file's "intent" based on technical red flags:
* **Suspicious Imports:** Flags combinations like `VirtualAllocEx` + `WriteProcessMemory` (Process Injection indicators).
* **Section Anomalies:** Detects non-standard names or mismatching characteristics (e.g., a writable `.text` section).
* **Entry Point Validation:** Identifies entry points located outside the primary code section.

### **3. Python-C Bridge (FFI)**
The UI controller utilizes `ctypes` to interface with the C engine, ensuring heavy computational tasks are handled at the native level while maintaining a flexible GUI.

---

## 🛠️ Architecture

* **Frontend:** Python (Modern Dashboard)
* **Backend Engine:** C (Native Win64 DLL)
* **Communication:** FFI via `ctypes`
* **Data Format:** Raw Binary Parsing

---

## 🚀 Getting Started

### **Installation**

1. **Clone the repository:**
```bash
git clone [https://github.com/yoadKochavi/Y-SHIELD.git](https://github.com/yoadKochavi/Y-SHIELD.git)
cd Y-SHIELD
