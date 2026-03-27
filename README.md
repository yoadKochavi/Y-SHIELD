🛡️ Y-SHIELD: Defensive PE Scanner Engine
Y-SHIELD is a high-performance, low-level security engine designed for static analysis of Windows Portable Executable (PE32+) files. Developed in C for the core analysis logic and Python for the frontend, it provides deep forensic insights into binary structures, entropy anomalies, and suspicious import patterns.

🚀 Key Capabilities
PE Forensics: Comprehensive parsing of DOS, NT, and Optional headers to extract EntryPoint, ImageBase, and Section characteristics.

Multi-Section Entropy Analysis: Implements Shannon Entropy calculations per section to detect packed, encrypted, or obfuscated payloads.

Import Table Forensics (IAT): A heuristic-based scoring system that monitors the IAT for "dangerous" API primitives (e.g., VirtualProtect, WinExec).

Signature Matching Engine: A thread-safe, byte-pattern scanner for identifying known malware families or packer stubs.

Composite Heuristic Scoring: Aggregates findings into a single risk verdict: CLEAN, SUSPICIOUS, or THREAT.

🛠️ Technical Implementation Details
The Core Engine (C / Win32 API)
Memory-Mapped I/O: Utilizes CreateFileMapping and MapViewOfFile for efficient analysis of large binaries without loading them entirely into memory.

RVA to Raw Offset Mapping: Implements manual calculation logic to translate Relative Virtual Addresses (RVA) to physical disk offsets.

Structured Exception Handling (SEH): Wrapped in __try/__except blocks to maintain stability when parsing malformed or malicious headers.

Thread-Safe Signature DB: Uses Win32 CRITICAL_SECTION to allow concurrent signature scanning across multiple threads.

The UI Layer (Python / Tkinter)
Native Interop: Leverages ctypes to bridge the Python UI with the C-based scanner.dll.

Asynchronous Processing: Scans are offloaded to background threads to prevent UI hangs during heavy I/O operations.

📊 Heuristic Logic & Scoring
The engine flags files based on several "red flags":

W+X Sections: Detection of sections marked as both Writeable and Executable (common in self-modifying code).

Entropy Thresholds: Alerts on sections with entropy > 7.4 (indicating heavy compression or encryption).

Zero-Import / Suspicious EP: Identifies binaries with missing import directories or entry points located in non-standard sections.

Suspicious API Clusters: High scores are assigned when combinations of process injection APIs (e.g., WriteProcessMemory, CreateRemoteThread) are found together.

⚙️ Building & Usage
Prerequisites
Compiler: MSVC (Visual Studio Build Tools) for x64.

Environment: Windows 10/11 x64.

Language: Python 3.10+.

1. Compilation (Core DLL)
Bash
cl.exe /LD /Fe:scanner.dll scanner.c /link /OPT:REF user32.lib
2. Running the UI
Bash
python ui.py
🛡️ Disclaimer
This project was developed for educational purposes and low-level research. It is intended as a forensic tool to understand binary structures and is not a replacement for a full AV/EDR solution.

Author: Yoad Kochavi

Role: Security Researcher & Low-Level Developer
