🛡️ Y-SHIELD: Advanced PE Forensics & Heuristic Engine
Y-SHIELD is a high-performance security research tool designed for Static PE Analysis. It bridges the gap between raw binary parsing and intuitive data visualization, providing researchers with the ability to detect packed executables, suspicious API patterns, and malicious indicators before execution.

🔬 Core Research Capabilities
1. High-Performance C Engine
The heart of Y-SHIELD is a native Win64 DLL written in C, optimized for memory efficiency and raw speed.

PE Header Reconstruction: Parses IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and Section Headers directly from the binary stream.

Entropy Analysis: Implements the Shannon Entropy algorithm to identify encrypted or packed sections (e.g., UPX, VMProtect).

IAT Mapping: Extracts the Import Address Table to identify high-risk API combinations.

2. Heuristic Threat Scoring
Instead of simple signature matching, Y-SHIELD uses a weighted scoring system to evaluate file "intent":

Suspicious Imports: Flags combinations like VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (Common Process Injection indicators).

Section Anomalies: Detects executable sections with non-standard names or mismatching characteristics (e.g., a writable .text section).

Entry Point Validation: Identifies entry points located outside the primary code section.

3. Python-C Bridge (FFI)
The UI controller utilizes ctypes to interface with the C engine, ensuring that heavy computational tasks are handled at the native level while maintaining a flexible, modern GUI.

🛠️ Architecture & Flow
קטע קוד
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
🚀 Getting Started
Prerequisites
Windows 10/11 x64

Python 3.10+

GCC / MinGW-w64 (For building from source)

Installation
Clone the repository:

Bash
git clone [https://github.com/yoadKochavi/Y-SHIELD.git](https://github.com/yoadKochavi/Y-SHIELD.git)
cd Y-SHIELD
Compile the Native Engine:

Bash
gcc -shared -o scanner.dll scanner.c -m64 -O3
Run the Application:

Bash
python main.py
🗺️ Roadmap
[ ] YARA Integration: Support for custom YARA rules scanning.

[ ] Recursive Directory Scan: Multi-threaded folder analysis.

[ ] Exportable Reports: Generate PDF/JSON forensics reports.

[ ] De-obfuscation: Basic string de-XORing for static analysis.

🤝 Contributing
Contributions are welcome! If you find a bug or have a suggestion for a new heuristic rule, feel free to open an Issue or a Pull Request.
