# 🛡️ Y-SHIELD: Defensive PE Scanner Engine

**Y-SHIELD** is a high-performance, low-level security engine designed for static analysis of Windows **Portable Executable (PE32+)** files. Developed in **C** for the core analysis logic and **Python** for the frontend, it provides deep forensic insights into binary structures, entropy anomalies, and suspicious import patterns.

---

## 🚀 Key Capabilities

* **PE Forensics:** Comprehensive parsing of DOS, NT, and Optional headers to extract EntryPoint, ImageBase, and Section characteristics.
* **Multi-Section Entropy Analysis:** Implements Shannon Entropy calculations per section to detect packed, encrypted, or obfuscated payloads (e.g., UPX, VMProtect).
* **Import Table Forensics (IAT):** A heuristic-based scoring system that monitors the Import Address Table for "dangerous" API primitives (e.g., `VirtualProtect`, `WinExec`, `URLDownloadToFile`).
* **Signature Matching Engine:** A thread-safe, byte-pattern scanner for identifying known malware families or packer stubs.
* **Composite Heuristic Scoring:** Aggregates findings into a single risk verdict: `CLEAN`, `SUSPICIOUS`, or `THREAT`.

---

## 🛠️ Technical Implementation Details

### The Core Engine (C / Win32 API)
The backbone of Y-SHIELD is a 64-bit DLL designed for speed and direct memory access:
* **Memory-Mapped I/O:** Utilizes `CreateFileMapping` and `MapViewOfFile` to analyze large binaries efficiently without exhausting the heap.
* **RVA to Raw Offset Mapping:** Implements manual calculation logic to translate Relative Virtual Addresses (RVA) to physical disk offsets—critical for accurate IAT parsing.
* **Structured Exception Handling (SEH):** Wrapped in `__try/__except` blocks to maintain stability when parsing malformed or "anti-analysis" PE headers.
* **Thread-Safe Signature DB:** Uses Win32 `CRITICAL_SECTION` to allow concurrent signature registration and scanning in multi-threaded environments.

### The UI Layer (Python / Tkinter)
* **Native Interop:** Leverages `ctypes` to bridge the Python UI with the C-based `scanner.dll`, ensuring low-level performance with a modern UX.
* **Asynchronous Processing:** Scans are offloaded to background threads to prevent UI hang during recursive directory I/O operations.

---

## 📊 Heuristic Logic & Scoring

The engine flags files based on several red flags:
1.  **W+X Sections:** Detection of sections marked as both *Writeable* and *Executable* (typical for self-modifying code).
2.  **Entropy Thresholds:** Alerts on sections with entropy > 7.4 (indicating compression/encryption).
3.  **Zero-Import/Zero-EP:** Identifies binaries with missing import directories or suspicious entry point locations.
4.  **Suspicious API Clusters:** High scores are assigned when combinations of process injection APIs are found together.

---

## ⚙️ Building & Usage

### Prerequisites
* **Compiler:** MSVC (Visual Studio Build Tools) for x64.
* **Environment:** Windows 10/11 x64.
* **Language:** Python 3.10+.

### Compilation (Core DLL)
```bash
cl.exe /LD /Fe:scanner.dll scanner.c /link /OPT:REF user32.lib

Running the UI
python ui.py

🛡️ Disclaimer
This project was developed for educational purposes and low-level research. It is intended as a forensic tool to understand binary structures and is not a replacement for a full AV/EDR solution.

Author: Yoad Kochavi

Aspiring Low-Level & Security Researcher

