# 🛡️ Y-SHIELD: Advanced PE Forensics & Heuristic Engine

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**Y-SHIELD** is a high-performance security research tool designed for **Static PE Analysis**. It bridges the gap between raw binary parsing and intuitive data visualization, providing researchers with the ability to detect packed executables and malicious indicators before execution.

---

## 🔬 Core Research Capabilities

### **1. High-Performance C Engine**
The heart of Y-SHIELD is a native Win64 DLL written in C, optimized for memory efficiency and raw speed.
* **PE Header Reconstruction:** Parses DOS and NT headers directly from the binary stream.
* **Entropy Analysis:** Calculates Shannon Entropy to detect packed or encrypted sections.
* **IAT Mapping:** Extracts the Import Address Table to identify high-risk API combinations.

### **2. Heuristic Threat Scoring**
Weighted scoring system to evaluate file "intent":
* **Suspicious Imports:** Flags combinations like `VirtualAllocEx` + `WriteProcessMemory` (Common Process Injection indicators).
* **Section Anomalies:** Detects non-standard names or writable code sections.

---

## 🚀 Getting Started

### **Installation**

1. **Clone the repository:**
```bash
git clone [https://github.com/yoadKochavi/Y-SHIELD.git](https://github.com/yoadKochavi/Y-SHIELD.git)
cd Y-SHIELD
