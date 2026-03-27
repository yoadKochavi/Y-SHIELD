# 🛡️ Y-SHIELD: Advanced PE Forensics & Heuristic Engine

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)

**Y-SHIELD** is a high-performance security research tool designed for **Static PE Analysis**. It bridges the gap between raw binary parsing and intuitive data visualization.

---

## 🔬 Core Research Capabilities

### **1. High-Performance C Engine**
The heart of Y-SHIELD is a native Win64 DLL written in C, optimized for memory efficiency.
* **PE Header Reconstruction:** Parses DOS and NT headers directly.
* **Entropy Analysis:** Calculates Shannon Entropy to detect packed sections.
* **IAT Mapping:** Extracts the Import Address Table for risk assessment.

### **2. Heuristic Threat Scoring**
Weighted scoring system to evaluate file "intent":
* **Suspicious Imports:** Flags `VirtualAllocEx`, `WriteProcessMemory`, etc.
* **Section Anomalies:** Detects non-standard names or writable code sections.

---

## 🛠️ Architecture & Flow

```mermaid
graph TD
    A[Portable Executable] --> B[Python UI Controller]
    B --> C{C-Bridge / ctypes}
    C --> D[Native Scanner.dll]
    D --> E[PE Header Parser]
    D --> F[Shannon Entropy Engine]
    D --> G[Heuristic Scorer]
    E & F & G --> H[JSON Report]
    H --> B
    B --> I[Visual Dashboard]
