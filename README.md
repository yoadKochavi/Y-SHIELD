# 🛡️ Y-SHIELD: Defensive PE Scanner Engine

![Language](https://img.shields.io/badge/Language-C%20%2B%20Python-blue) 
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-green)
![Status](https://img.shields.io/badge/Status-Research-yellow)

**Y-SHIELD** is a **high-performance, low-level security engine** for static analysis of Windows **PE32+ binaries**.  
Built in **C** (core engine) and **Python** (UI), it provides deep forensic insights into binaries, entropy anomalies, and suspicious imports.

---

## 🚀 Key Capabilities

- 🧩 **PE Forensics:** Parses DOS, NT, and Optional headers to extract EntryPoint, ImageBase, and section characteristics.  
- 🔍 **Multi-Section Entropy Analysis:** Shannon entropy per section to detect packed, encrypted, or obfuscated payloads.  
- ⚡ **Import Table Forensics (IAT):** Heuristic scoring for “dangerous” APIs like `VirtualProtect` & `WinExec`.  
- 🛠 **Signature Matching Engine:** Thread-safe byte-pattern scanner for known malware families and packers.  
- 📊 **Composite Heuristic Scoring:** Aggregates findings into `CLEAN`, `SUSPICIOUS`, or `THREAT`.

---

## 🛠 Technical Implementation

### 🔹 Core Engine (C / Win32 API)
- 💾 **Memory-Mapped I/O:** `CreateFileMapping` + `MapViewOfFile` for fast analysis without full memory load.  
- 🔄 **RVA ↔ Raw Offset Mapping:** Manual calculation logic for disk offsets.  
- 🛡 **Structured Exception Handling (SEH):** `__try/__except` ensures stability on malformed binaries.  
- ⚙️ **Thread-Safe Signature DB:** `CRITICAL_SECTION` for concurrent scanning.

### 🔹 UI Layer (Python / Tkinter)
- 🐍 **Native Interop:** `ctypes` bridges Python UI with `scanner.dll`.  
- ⏱ **Async Processing:** Background scanning prevents UI hangs during heavy I/O.

---

## 📊 Heuristic Logic & Scoring

Red flags detected by Y-SHIELD:

1. 🔥 **W+X Sections:** Sections marked **Writeable + Executable** (typical in self-modifying code).  
2. 📈 **High Entropy:** Sections with entropy > 7.4 indicate compression or encryption.  
3. ❌ **Zero-Import / Suspicious EP:** Missing import directories or EntryPoint in non-standard sections.  
4. ⚠️ **Suspicious API Clusters:** High score for combinations like `WriteProcessMemory` + `CreateRemoteThread`.

---

## ⚙️ Build & Usage

### 📋 Prerequisites
- **Compiler:** MSVC (Visual Studio Build Tools) x64  
- **Environment:** Windows 10/11 x64  
- **Python:** 3.10+

### 1️⃣ Compile Core DLL
```bash
cl.exe /LD /Fe:scanner.dll scanner.c /link /OPT:REF user32.lib
```

### 2️⃣ Run the UI
```bash
python ui.py
```

🛡️ Disclaimer
This project is for educational and low-level research purposes only. It is a forensic tool to understand binary structures and not a replacement for full AV/EDR solutions.

Author: Yoad Kochavi

Security Researcher & Low-Level Engineer
