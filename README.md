# 🛡️ Y-SHIELD: Advanced PE Forensics & Heuristic Engine

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows_x64-lightgrey.svg)
![Language](https://img.shields.io/badge/language-C%20%2F%20Python-green.svg)

**Y-SHIELD** is a low-level security research tool designed for deep static analysis of Portable Executable (PE) files. It leverages a high-performance C engine for raw binary parsing and a Python-based GUI for intuitive data visualization.

## 🚀 Key Low-Level Features
* **Deep PE Parsing:** Extraction of Entry Point, Image Base, and Section headers.
* **Entropy Analysis:** Shannon Entropy calculation to detect packed or encrypted sections (common malware indicators).
* **Heuristic Scoring:** A dynamic threat scoring system based on suspicious API imports (e.g., `WriteProcessMemory`, `CreateRemoteThread`).
* **Signature Matching:** Fast byte-pattern scanning against a signature database.
* **Memory Safety:** Implemented with custom exception handling to ensure robust scanning.

## 🎥 Demonstration
![Main Dashboard](ui_scan.png)
*(Note: Upload your screenshot named 'ui_scan.png' to the repository to see it here)*

## 🛠️ Architecture
- **Core Engine (`scanner.c/h`):** High-efficiency logic compiled into a Win64 DLL.
- **UI Controller (`main.py`):** Python dashboard using `ctypes` to bridge with the native C engine.

## ⚡ How to Run
### Option 1: Quick Start (Recommended)
1. Download the latest **ZIP** from the [Releases](https://github.com/yoadKochavi/Y-SHIELD/releases) section.
2. Extract all files to a folder.
3. Run `Y-SHIELD.exe`.

### Option 2: Build from Source
Requires GCC/MinGW for the C engine:
```bash
# Compile the DLL
gcc -shared -o scanner.dll scanner.c

# Run the UI
python main.py
