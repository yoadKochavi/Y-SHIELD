"""
Y-SHIELD (Defensive) UI

This is a defensive, file-based scanner UI. It loads `scanner.dll` and provides:
- Composite scan (PE metadata + entropy + imports + signature scan)
- Section entropy table
- Flagged import table
- Scan history with export
- Signature registration (hex pattern)

CREATOR - YOAD KOCHAVI

No external dependencies required (Tkinter only).
"""

import ctypes
import os
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ============================= scanner.h mirror =============================

Y_MAX_SECTIONS = 256
Y_MAX_SIG_NAME = 64
Y_MAX_IMPORT_DLLS = 128
Y_MAX_DLL_NAME = 64
Y_MAX_FLAGGED_IMPORTS = 64
MAX_PATH = 260

DWORD = wintypes.DWORD
BOOL = wintypes.BOOL  # Win32 BOOL is 4 bytes


class YPEMetadata(ctypes.Structure):
    _fields_ = [
        ("dwEntryPoint", DWORD),
        ("dwImageBase", DWORD),
        ("dwSizeOfImage", DWORD),
        ("dwSectionCount", DWORD),
        ("bHasWriteExec", BOOL),
        ("bIsDotNet", BOOL),
        ("bIsDll", BOOL),
        ("szPrimarySection", ctypes.c_char * 16),
        ("dwEntropy", DWORD),
    ]


class YSectionEntropy(ctypes.Structure):
    _fields_ = [
        ("szName", ctypes.c_char * 10),
        ("dwEntropy", DWORD),
        ("dwRawSize", DWORD),
        ("dwVirtSize", DWORD),
        ("dwChars", DWORD),
        ("bSuspicious", BOOL),
    ]


class YMatchResult(ctypes.Structure):
    _fields_ = [
        ("szSigName", ctypes.c_char * Y_MAX_SIG_NAME),
        ("dwOffset", DWORD),
        ("dwSeverity", DWORD),
        ("dwSigIndex", DWORD),
    ]


class YFlaggedImport(ctypes.Structure):
    _fields_ = [
        ("szApi", ctypes.c_char * 64),
        ("szDll", ctypes.c_char * 64),
        ("szReason", ctypes.c_char * 128),
        ("dwScore", DWORD),
    ]


class YImportReport(ctypes.Structure):
    _fields_ = [
        ("szDlls", (ctypes.c_char * Y_MAX_DLL_NAME) * Y_MAX_IMPORT_DLLS),
        ("dwDllCount", DWORD),
        ("dwTotalImports", DWORD),
        ("dwThreatScore", DWORD),
        ("dwFlaggedCount", DWORD),
        ("flagged", YFlaggedImport * Y_MAX_FLAGGED_IMPORTS),
    ]


class YThreatReport(ctypes.Structure):
    _fields_ = [
        ("szFilePath", ctypes.c_char * MAX_PATH),
        ("dwTimestamp", DWORD),
        ("dwScore", DWORD),
        ("dwFlags", DWORD),
        ("dwFinalVerdict", DWORD),
        ("dwSectionCount", DWORD),
        ("pe", YPEMetadata),
        ("sections", YSectionEntropy * Y_MAX_SECTIONS),
        ("imports", YImportReport),
        ("sigMatch", YMatchResult),
    ]


Y_STATUS_CLEAN = 0x00000000
Y_STATUS_THREAT = 0x00000001
Y_STATUS_SUSPICIOUS = 0x00000002


def decode_cstr(buf: bytes) -> str:
    return buf.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def fmt_entropy(v100: int) -> str:
    return f"{v100 // 100}.{v100 % 100:02d}"


def verdict_label(code: int) -> str:
    return {0: "CLEAN", 1: "THREAT", 2: "SUSPICIOUS"}.get(code, f"ERROR(0x{code:08X})")


def parse_hex_bytes(s: str) -> bytes:
    parts = [p for p in s.replace(",", " ").split() if p]
    return bytes(int(p, 16) for p in parts)


# ============================= Engine wrapper =============================


class Engine:
    def __init__(self, dll_path: str = "scanner.dll"):
        self.dll_path = dll_path
        self.demo_mode = False
        self.lib: ctypes.CDLL | None = None
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.dll_path):
            self.demo_mode = True
            return
        try:
            self.lib = ctypes.CDLL(os.path.abspath(self.dll_path))
            self._bind()
        except OSError:
            self.demo_mode = True

    def _bind(self) -> None:
        assert self.lib is not None
        lib = self.lib
        u32 = ctypes.c_uint32
        cstr = ctypes.c_char_p
        byte_p = ctypes.c_char_p

        lib.YShield_Version.restype = u32
        lib.YShield_Version.argtypes = [ctypes.POINTER(u32), ctypes.POINTER(u32), ctypes.POINTER(u32)]

        lib.Sigdb_Initialize.restype = u32
        lib.Sigdb_Initialize.argtypes = []

        lib.Sigdb_RegisterSignature.restype = u32
        lib.Sigdb_RegisterSignature.argtypes = [cstr, byte_p, u32, u32]

        lib.Heuristic_CompositeScan.restype = u32
        lib.Heuristic_CompositeScan.argtypes = [cstr, ctypes.POINTER(YThreatReport)]

        lib.Scan_ImportTableForensics.restype = u32
        lib.Scan_ImportTableForensics.argtypes = [cstr, ctypes.POINTER(YImportReport)]

        lib.Utility_AnalyzeSectionEntropy.restype = u32
        lib.Utility_AnalyzeSectionEntropy.argtypes = [cstr, ctypes.POINTER(YSectionEntropy), u32]

        lib.Report_Serialize.restype = u32
        lib.Report_Serialize.argtypes = [ctypes.POINTER(YThreatReport), ctypes.c_char_p, u32]

        lib.Scan_RecursiveDiskIO.restype = u32
        lib.Scan_RecursiveDiskIO.argtypes = [cstr, byte_p, u32]

    def boot(self) -> str:
        if self.demo_mode:
            return "DEMO MODE (scanner.dll missing or failed to load)"
        assert self.lib is not None
        with self._lock:
            maj = ctypes.c_uint32()
            mi = ctypes.c_uint32()
            pa = ctypes.c_uint32()
            self.lib.YShield_Version(ctypes.byref(maj), ctypes.byref(mi), ctypes.byref(pa))
            self.lib.Sigdb_Initialize()
        return f"Engine loaded: v{maj.value}.{mi.value}.{pa.value}"

    def composite(self, path: str) -> tuple[int, YThreatReport]:
        report = YThreatReport()
        if self.demo_mode:
            report.dwScore = 42
            report.dwFinalVerdict = Y_STATUS_SUSPICIOUS
            report.dwSectionCount = 0
            return Y_STATUS_SUSPICIOUS, report
        assert self.lib is not None
        with self._lock:
            code = int(self.lib.Heuristic_CompositeScan(path.encode("utf-8"), ctypes.byref(report)))
        return code, report

    def serialize(self, report: YThreatReport) -> str:
        if self.demo_mode:
            return "DEMO REPORT\n"
        assert self.lib is not None
        buf = ctypes.create_string_buffer(65536)
        with self._lock:
            self.lib.Report_Serialize(ctypes.byref(report), buf, len(buf))
        return buf.value.decode("utf-8", errors="replace")

    def register_signature(self, name: str, pattern: bytes, severity: int) -> int:
        if self.demo_mode:
            return 0
        assert self.lib is not None
        with self._lock:
            return int(self.lib.Sigdb_RegisterSignature(name.encode("utf-8"), pattern, len(pattern), severity))

    def disk_scan(self, path: str, pattern: bytes) -> int:
        if self.demo_mode:
            return Y_STATUS_CLEAN
        assert self.lib is not None
        with self._lock:
            return int(self.lib.Scan_RecursiveDiskIO(path.encode("utf-8"), pattern, len(pattern)))


# ============================= History =============================


@dataclass
class HistoryItem:
    ts: datetime
    target: str
    verdict: str
    score: int
    flags: int
    detail: str


class HistoryStore:
    def __init__(self, max_items: int = 500):
        self._max = max_items
        self._items: list[HistoryItem] = []
        self._lock = threading.Lock()

    def add(self, item: HistoryItem) -> None:
        with self._lock:
            self._items.insert(0, item)
            if len(self._items) > self._max:
                self._items.pop()

    def items(self) -> list[HistoryItem]:
        with self._lock:
            return list(self._items)

    def export_text(self) -> str:
        with self._lock:
            lines = []
            lines.append(f"Y-SHIELD HISTORY  {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            lines.append("=" * 70 + "\n")
            for it in self._items:
                lines.append(
                    f"[{it.ts:%H:%M:%S}] {it.verdict:<11} score={it.score:<3} flags=0x{it.flags:08X}  {it.target}\n"
                )
            return "".join(lines)


# ============================= UI =============================


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Y-SHIELD (Defensive)")
        self.geometry("1220x780")
        self.minsize(980, 620)

        self.engine = Engine("scanner.dll")
        self.history = HistoryStore()

        self.status_var = tk.StringVar(value="Initializing…")
        self.target_var = tk.StringVar(value="")
        self.verdict_var = tk.StringVar(value="—")

        self._build()
        self.status_var.set(self.engine.boot())

    def _build(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Status:").pack(side="left")
        ttk.Label(top, textvariable=self.status_var).pack(side="left", padx=(6, 20))
        ttk.Button(top, text="Open File…", command=self.pick_file).pack(side="right")
        ttk.Button(top, text="Composite Scan", command=self.run_composite).pack(side="right", padx=8)

        row = ttk.Frame(self, padding=(10, 0, 10, 10))
        row.pack(fill="x")
        ttk.Label(row, text="Target:").pack(side="left")
        ttk.Entry(row, textvariable=self.target_var).pack(side="left", fill="x", expand=True, padx=8)

        banner = ttk.Frame(self, padding=(10, 0, 10, 10))
        banner.pack(fill="x")
        ttk.Label(banner, text="Verdict:").pack(side="left")
        ttk.Label(banner, textvariable=self.verdict_var, font=("Segoe UI", 12, "bold")).pack(side="left", padx=8)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tab_scan = ttk.Frame(self.nb, padding=8)
        self.tab_history = ttk.Frame(self.nb, padding=8)
        self.tab_sig = ttk.Frame(self.nb, padding=8)
        self.tab_disk = ttk.Frame(self.nb, padding=8)
        self.nb.add(self.tab_scan, text="Scan Details")
        self.nb.add(self.tab_history, text="History")
        self.nb.add(self.tab_sig, text="Signatures")
        self.nb.add(self.tab_disk, text="Disk Pattern Scan")

        self._build_scan_tab()
        self._build_history_tab()
        self._build_sig_tab()
        self._build_disk_tab()

    # --- Scan tab ---

    def _build_scan_tab(self) -> None:
        pan = ttk.PanedWindow(self.tab_scan, orient="horizontal")
        pan.pack(fill="both", expand=True)

        left = ttk.Frame(pan, padding=6)
        right = ttk.Frame(pan, padding=6)
        pan.add(left, weight=1)
        pan.add(right, weight=2)

        ttk.Label(left, text="Section Entropy").pack(anchor="w")
        self.ent_tree = ttk.Treeview(left, columns=("name", "entropy", "raw", "virt", "sus"), show="headings", height=18)
        for col, w in [("name", 90), ("entropy", 80), ("raw", 90), ("virt", 90), ("sus", 70)]:
            self.ent_tree.heading(col, text=col.upper())
            self.ent_tree.column(col, width=w, anchor="w")
        self.ent_tree.pack(fill="both", expand=True, pady=(6, 10))

        ttk.Label(left, text="Flagged Imports").pack(anchor="w")
        self.imp_tree = ttk.Treeview(left, columns=("score", "dll", "api", "reason"), show="headings", height=10)
        for col, w in [("score", 60), ("dll", 110), ("api", 150), ("reason", 220)]:
            self.imp_tree.heading(col, text=col.upper())
            self.imp_tree.column(col, width=w, anchor="w")
        self.imp_tree.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Raw Report").pack(anchor="w")
        self.report_txt = tk.Text(right, wrap="none")
        self.report_txt.pack(fill="both", expand=True, pady=(6, 0))
        self.report_txt.configure(state="disabled")

    # --- History tab ---

    def _build_history_tab(self) -> None:
        ctrl = ttk.Frame(self.tab_history)
        ctrl.pack(fill="x")
        ttk.Button(ctrl, text="Refresh", command=self.refresh_history).pack(side="left")
        ttk.Button(ctrl, text="Export TXT…", command=self.export_history).pack(side="left", padx=8)
        ttk.Button(ctrl, text="Clear", command=self.clear_history).pack(side="left")

        self.hist_tree = ttk.Treeview(self.tab_history, columns=("time", "verdict", "score", "flags", "target"), show="headings")
        for col, w in [("time", 120), ("verdict", 110), ("score", 70), ("flags", 120), ("target", 650)]:
            self.hist_tree.heading(col, text=col.upper())
            self.hist_tree.column(col, width=w, anchor="w")
        self.hist_tree.pack(fill="both", expand=True, pady=(8, 0))

        self.hist_tree.bind("<<TreeviewSelect>>", self._on_hist_select)
        self.hist_detail = tk.Text(self.tab_history, height=10, wrap="none")
        self.hist_detail.pack(fill="x", pady=(8, 0))
        self.hist_detail.configure(state="disabled")

    # --- Signatures tab ---

    def _build_sig_tab(self) -> None:
        ttk.Label(self.tab_sig, text="Register a custom signature (hex bytes, space separated).").pack(anchor="w")
        frm = ttk.Frame(self.tab_sig)
        frm.pack(fill="x", pady=8)

        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky="w")
        self.sig_name = ttk.Entry(frm, width=40)
        self.sig_name.grid(row=0, column=1, sticky="we", padx=8)

        ttk.Label(frm, text="Severity:").grid(row=0, column=2, sticky="w")
        self.sig_sev = ttk.Combobox(frm, values=["0", "1", "2", "3", "4"], width=5, state="readonly")
        self.sig_sev.set("3")
        self.sig_sev.grid(row=0, column=3, sticky="w", padx=8)

        ttk.Label(frm, text="Pattern:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.sig_pat = ttk.Entry(frm)
        self.sig_pat.grid(row=1, column=1, columnspan=3, sticky="we", padx=8, pady=(8, 0))

        frm.columnconfigure(1, weight=1)

        ttk.Button(self.tab_sig, text="Register", command=self.register_sig).pack(anchor="w")
        self.sig_log = tk.Text(self.tab_sig, height=12, wrap="none")
        self.sig_log.pack(fill="both", expand=True, pady=(8, 0))
        self.sig_log.configure(state="disabled")

    # --- Disk tab ---

    def _build_disk_tab(self) -> None:
        ttk.Label(self.tab_disk, text="Recursive disk scan: find a byte pattern inside files under a folder.").pack(anchor="w")
        frm = ttk.Frame(self.tab_disk)
        frm.pack(fill="x", pady=8)

        ttk.Label(frm, text="Folder:").grid(row=0, column=0, sticky="w")
        self.disk_path = ttk.Entry(frm)
        self.disk_path.grid(row=0, column=1, sticky="we", padx=8)
        ttk.Button(frm, text="Browse…", command=self.pick_folder).grid(row=0, column=2, sticky="w")

        ttk.Label(frm, text="Pattern (hex):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.disk_pat = ttk.Entry(frm)
        self.disk_pat.grid(row=1, column=1, sticky="we", padx=8, pady=(8, 0))
        ttk.Button(frm, text="Scan", command=self.run_disk_scan).grid(row=1, column=2, sticky="w", pady=(8, 0))

        frm.columnconfigure(1, weight=1)

        self.disk_out = tk.Text(self.tab_disk, height=18, wrap="none")
        self.disk_out.pack(fill="both", expand=True, pady=(8, 0))
        self.disk_out.configure(state="disabled")

    # --- Actions ---

    def pick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select file",
            filetypes=[("Executables", "*.exe *.dll *.sys *.ocx"), ("All files", "*.*")]
        )
        if path:
            self.target_var.set(path)

    def pick_folder(self) -> None:
        p = filedialog.askdirectory(title="Select folder")
        if p:
            self.disk_path.delete(0, "end")
            self.disk_path.insert(0, p)

    def run_composite(self) -> None:
        path = self.target_var.get().strip()
        if not path:
            messagebox.showwarning("No file", "Pick a file first.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Missing", "That file does not exist.")
            return

        self.verdict_var.set("SCANNING…")
        self._clear_tree(self.ent_tree)
        self._clear_tree(self.imp_tree)
        self._set_text(self.report_txt, "")

        threading.Thread(target=self._composite_worker, args=(path,), daemon=True).start()

    def _composite_worker(self, path: str) -> None:
        t0 = time.time()
        code, report = self.engine.composite(path)
        elapsed = time.time() - t0
        txt = self.engine.serialize(report)

        def ui() -> None:
            self.verdict_var.set(
                f"{verdict_label(code)}  (score={int(report.dwScore)} flags=0x{int(report.dwFlags):08X}  {elapsed:.2f}s)"
            )
            self._set_text(self.report_txt, txt)

            for i in range(int(report.dwSectionCount)):
                s = report.sections[i]
                self.ent_tree.insert(
                    "", "end",
                    values=(decode_cstr(bytes(s.szName)),
                            fmt_entropy(int(s.dwEntropy)),
                            int(s.dwRawSize),
                            int(s.dwVirtSize),
                            "YES" if int(s.bSuspicious) else "NO")
                )

            imp = report.imports
            for i in range(int(imp.dwFlaggedCount)):
                f = imp.flagged[i]
                self.imp_tree.insert(
                    "", "end",
                    values=(int(f.dwScore),
                            decode_cstr(bytes(f.szDll)),
                            decode_cstr(bytes(f.szApi)),
                            decode_cstr(bytes(f.szReason)))
                )

            item = HistoryItem(
                ts=datetime.now(),
                target=path,
                verdict=verdict_label(code),
                score=int(report.dwScore),
                flags=int(report.dwFlags),
                detail=txt,
            )
            self.history.add(item)
            self.refresh_history()

        self.after(0, ui)

    def register_sig(self) -> None:
        name = self.sig_name.get().strip()
        sev_s = self.sig_sev.get().strip()
        pat_s = self.sig_pat.get().strip()
        if not name or not pat_s:
            self._sig_log("[ERROR] Name and pattern are required.\n")
            return
        try:
            pat = parse_hex_bytes(pat_s)
        except Exception:
            self._sig_log("[ERROR] Invalid hex pattern.\n")
            return
        if not pat:
            self._sig_log("[ERROR] Pattern is empty.\n")
            return
        try:
            sev = int(sev_s)
        except ValueError:
            sev = 3
        r = self.engine.register_signature(name, pat, sev)
        if r == 0:
            self._sig_log(f"[OK] Registered '{name}' ({len(pat)} bytes) sev={sev}\n")
        else:
            self._sig_log(f"[ERROR] Engine returned 0x{r:08X}\n")

    def run_disk_scan(self) -> None:
        folder = self.disk_path.get().strip()
        pat_s = self.disk_pat.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Folder", "Select a valid folder.")
            return
        try:
            pat = parse_hex_bytes(pat_s)
        except Exception:
            messagebox.showwarning("Pattern", "Invalid hex pattern.")
            return
        if not pat:
            messagebox.showwarning("Pattern", "Pattern is empty.")
            return
        self._set_text(self.disk_out, "Scanning…\n")
        threading.Thread(target=self._disk_worker, args=(folder, pat), daemon=True).start()

    def _disk_worker(self, folder: str, pat: bytes) -> None:
        r = self.engine.disk_scan(folder, pat)
        msg = "THREAT (pattern found)\n" if r == Y_STATUS_THREAT else \
              "CLEAN (pattern not found)\n" if r == Y_STATUS_CLEAN else \
              f"ERROR 0x{r:08X}\n"
        self.after(0, lambda: self._set_text(self.disk_out, msg))

    # --- History helpers ---

    def refresh_history(self) -> None:
        self._clear_tree(self.hist_tree)
        for it in self.history.items():
            self.hist_tree.insert(
                "", "end",
                values=(it.ts.strftime("%Y-%m-%d %H:%M:%S"), it.verdict, it.score, f"0x{it.flags:08X}", it.target)
            )

    def export_history(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export history",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")]
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.history.export_text())
        messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def clear_history(self) -> None:
        if not messagebox.askyesno("Clear history", "Delete all history items?"):
            return
        self.history = HistoryStore()
        self.refresh_history()
        self._set_text(self.hist_detail, "")

    def _on_hist_select(self, _evt) -> None:
        sel = self.hist_tree.selection()
        if not sel:
            return
        idx = self.hist_tree.index(sel[0])
        items = self.history.items()
        if idx < 0 or idx >= len(items):
            return
        it = items[idx]
        self._set_text(self.hist_detail, it.detail)

    # --- UI utility ---

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        for i in tree.get_children():
            tree.delete(i)

    @staticmethod
    def _set_text(widget: tk.Text, s: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", s)
        widget.configure(state="disabled")

    def _sig_log(self, s: str) -> None:
        self.sig_log.configure(state="normal")
        self.sig_log.insert("end", s)
        self.sig_log.configure(state="disabled")
        self.sig_log.see("end")


if __name__ == "__main__":
    App().mainloop()

"""
Y-SHIELD (Defensive) — minimal, stable UI

Loads `scanner.dll` via ctypes and runs file-based analysis:
- Composite scan (PE structure + entropy + imports + sigdb)
- Displays section entropy table and raw report text.

No external dependencies required.
"""

import ctypes
import os
import threading
import time
from ctypes import wintypes
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ============================= scanner.h mirror =============================

Y_MAX_SECTIONS = 256
Y_MAX_SIG_NAME = 64
Y_MAX_IMPORT_DLLS = 128
Y_MAX_DLL_NAME = 64
Y_MAX_FLAGGED_IMPORTS = 64
MAX_PATH = 260

DWORD = wintypes.DWORD
BOOL = wintypes.BOOL  # Win32 BOOL is 4 bytes


class YPEMetadata(ctypes.Structure):
    _fields_ = [
        ("dwEntryPoint", DWORD),
        ("dwImageBase", DWORD),
        ("dwSizeOfImage", DWORD),
        ("dwSectionCount", DWORD),
        ("bHasWriteExec", BOOL),
        ("bIsDotNet", BOOL),
        ("bIsDll", BOOL),
        ("szPrimarySection", ctypes.c_char * 16),
        ("dwEntropy", DWORD),
    ]


class YSectionEntropy(ctypes.Structure):
    _fields_ = [
        ("szName", ctypes.c_char * 10),
        ("dwEntropy", DWORD),
        ("dwRawSize", DWORD),
        ("dwVirtSize", DWORD),
        ("dwChars", DWORD),
        ("bSuspicious", BOOL),
    ]


class YMatchResult(ctypes.Structure):
    _fields_ = [
        ("szSigName", ctypes.c_char * Y_MAX_SIG_NAME),
        ("dwOffset", DWORD),
        ("dwSeverity", DWORD),
        ("dwSigIndex", DWORD),
    ]


class YFlaggedImport(ctypes.Structure):
    _fields_ = [
        ("szApi", ctypes.c_char * 64),
        ("szDll", ctypes.c_char * 64),
        ("szReason", ctypes.c_char * 128),
        ("dwScore", DWORD),
    ]


class YImportReport(ctypes.Structure):
    _fields_ = [
        ("szDlls", (ctypes.c_char * Y_MAX_DLL_NAME) * Y_MAX_IMPORT_DLLS),
        ("dwDllCount", DWORD),
        ("dwTotalImports", DWORD),
        ("dwThreatScore", DWORD),
        ("dwFlaggedCount", DWORD),
        ("flagged", YFlaggedImport * Y_MAX_FLAGGED_IMPORTS),
    ]


class YThreatReport(ctypes.Structure):
    _fields_ = [
        ("szFilePath", ctypes.c_char * MAX_PATH),
        ("dwTimestamp", DWORD),
        ("dwScore", DWORD),
        ("dwFlags", DWORD),
        ("dwFinalVerdict", DWORD),
        ("dwSectionCount", DWORD),
        ("pe", YPEMetadata),
        ("sections", YSectionEntropy * Y_MAX_SECTIONS),
        ("imports", YImportReport),
        ("sigMatch", YMatchResult),
    ]


Y_STATUS_CLEAN = 0x00000000
Y_STATUS_THREAT = 0x00000001
Y_STATUS_SUSPICIOUS = 0x00000002


def _decode_cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _fmt_entropy(v100: int) -> str:
    return f"{v100 // 100}.{v100 % 100:02d}"


def _verdict_label(code: int) -> str:
    return {0: "CLEAN", 1: "THREAT", 2: "SUSPICIOUS"}.get(code, f"ERROR(0x{code:08X})")


# ============================= Engine wrapper =============================


class Engine:
    def __init__(self, dll_path: str = "scanner.dll"):
        self.dll_path = dll_path
        self.demo_mode = False
        self.lib: ctypes.CDLL | None = None
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.dll_path):
            self.demo_mode = True
            return
        try:
            self.lib = ctypes.CDLL(os.path.abspath(self.dll_path))
            self._bind()
        except OSError:
            self.demo_mode = True

    def _bind(self) -> None:
        assert self.lib is not None
        lib = self.lib
        u32 = ctypes.c_uint32
        cstr = ctypes.c_char_p

        lib.YShield_Version.restype = u32
        lib.YShield_Version.argtypes = [ctypes.POINTER(u32), ctypes.POINTER(u32), ctypes.POINTER(u32)]

        lib.Sigdb_Initialize.restype = u32
        lib.Sigdb_Initialize.argtypes = []

        lib.Heuristic_CompositeScan.restype = u32
        lib.Heuristic_CompositeScan.argtypes = [cstr, ctypes.POINTER(YThreatReport)]

        lib.Report_Serialize.restype = u32
        lib.Report_Serialize.argtypes = [ctypes.POINTER(YThreatReport), ctypes.c_char_p, u32]

    def boot(self) -> str:
        if self.demo_mode:
            return "DEMO MODE (scanner.dll missing or failed to load)"
        assert self.lib is not None
        with self._lock:
            maj = ctypes.c_uint32()
            mi = ctypes.c_uint32()
            pa = ctypes.c_uint32()
            self.lib.YShield_Version(ctypes.byref(maj), ctypes.byref(mi), ctypes.byref(pa))
            self.lib.Sigdb_Initialize()
        return f"Engine loaded: v{maj.value}.{mi.value}.{pa.value}"

    def composite(self, path: str) -> tuple[int, YThreatReport]:
        report = YThreatReport()
        if self.demo_mode:
            report.dwScore = 42
            report.dwFinalVerdict = Y_STATUS_SUSPICIOUS
            return Y_STATUS_SUSPICIOUS, report
        assert self.lib is not None
        with self._lock:
            code = self.lib.Heuristic_CompositeScan(path.encode("utf-8"), ctypes.byref(report))
        return int(code), report

    def serialize(self, report: YThreatReport) -> str:
        if self.demo_mode:
            return "DEMO REPORT\n"
        assert self.lib is not None
        buf = ctypes.create_string_buffer(65536)
        with self._lock:
            self.lib.Report_Serialize(ctypes.byref(report), buf, len(buf))
        return buf.value.decode("utf-8", errors="replace")


# ============================= UI =============================


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Y-SHIELD (Defensive)")
        self.geometry("1100x720")
        self.minsize(900, 600)

        self.engine = Engine("scanner.dll")
        self.status_var = tk.StringVar(value="Initializing…")
        self.path_var = tk.StringVar(value="")
        self.verdict_var = tk.StringVar(value="—")

        self._build()
        self.status_var.set(self.engine.boot())

    def _build(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Status:").pack(side="left")
        ttk.Label(top, textvariable=self.status_var).pack(side="left", padx=(6, 20))

        ttk.Button(top, text="Open File…", command=self.pick_file).pack(side="right")
        ttk.Button(top, text="Composite Scan", command=self.run_scan).pack(side="right", padx=8)

        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(fill="x")
        ttk.Label(mid, text="Target:").pack(side="left")
        ttk.Entry(mid, textvariable=self.path_var).pack(side="left", fill="x", expand=True, padx=8)

        banner = ttk.Frame(self, padding=(10, 0, 10, 10))
        banner.pack(fill="x")
        ttk.Label(banner, text="Verdict:").pack(side="left")
        ttk.Label(banner, textvariable=self.verdict_var, font=("Segoe UI", 12, "bold")).pack(side="left", padx=8)

        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(body, padding=6)
        right = ttk.Frame(body, padding=6)
        body.add(left, weight=1)
        body.add(right, weight=2)

        ttk.Label(left, text="Section Entropy").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("name", "entropy", "raw", "virt", "sus"), show="headings", height=18)
        for col, w in [("name", 90), ("entropy", 80), ("raw", 90), ("virt", 90), ("sus", 70)]:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Raw Report").pack(anchor="w")
        self.txt = tk.Text(right, wrap="none")
        self.txt.pack(fill="both", expand=True, pady=(6, 0))
        self.txt.configure(state="disabled")

    def pick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select file",
            filetypes=[("Executables", "*.exe *.dll *.sys *.ocx"), ("All files", "*.*")]
        )
        if path:
            self.path_var.set(path)

    def run_scan(self) -> None:
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("No file", "Pick a file first.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Missing", "That file does not exist.")
            return

        self.verdict_var.set("SCANNING…")
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._set_text("")

        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def _scan_worker(self, path: str) -> None:
        t0 = time.time()
        code, report = self.engine.composite(path)
        elapsed = time.time() - t0
        txt = self.engine.serialize(report)

        def ui() -> None:
            self.verdict_var.set(
                f"{_verdict_label(code)}  (score={int(report.dwScore)} flags=0x{int(report.dwFlags):08X}  {elapsed:.2f}s)"
            )
            self._set_text(txt)
            for i in range(int(report.dwSectionCount)):
                s = report.sections[i]
                name = _decode_cstr(bytes(s.szName))
                self.tree.insert(
                    "", "end",
                    values=(name, _fmt_entropy(int(s.dwEntropy)), int(s.dwRawSize), int(s.dwVirtSize),
                            "YES" if int(s.bSuspicious) else "NO")
                )

        self.after(0, ui)

    def _set_text(self, s: str) -> None:
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", s)
        self.txt.configure(state="disabled")


if __name__ == "__main__":
    App().mainloop()

