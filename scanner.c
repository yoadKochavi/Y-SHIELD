/*
 * Y-SHIELD DEFENSIVE SCANNER ENGINE
 * FILE: scanner.c
 *
 * Build: scanner.dll (Windows x64)
 * Focus:
 * - PE structure metadata (x64 PE32+)
 * - Section entropy analysis
 * - Import table forensics (watchlist scoring)
 * - Signature database (thread-safe registration + scanning)
 * - Composite heuristic scoring + report serialization
 * - Recursive disk scan (byte pattern)
 *
 * CREATOR - YOAD KOCHAVI
 * 
 * SECURITY NOTE:
 * - No privilege escalation.
 * - No arbitrary remote-process memory scanning (export present only for API compatibility).
 */

#define _CRT_SECURE_NO_WARNINGS
#include "scanner.h"

#include <math.h>
#include <time.h>
#include <string.h>

/* ============================== INTERNAL LOG ============================== */

static void _CoreLog(const char* fmt, ...) {
    char buffer[Y_MAX_LOG_MESSAGE];
    va_list args;
    va_start(args, fmt);
    _vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    OutputDebugStringA(buffer);
}

/* ============================== UTILITIES ============================== */

static void _SafeStrCopy(char* dst, size_t dstCap, const char* src) {
    if (!dst || dstCap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dstCap - 1);
    dst[dstCap - 1] = '\0';
}

static DWORD _RvaToOffset(DWORD rva, const IMAGE_SECTION_HEADER* pSec, DWORD nSec) {
    for (DWORD i = 0; i < nSec; i++) {
        DWORD va  = pSec[i].VirtualAddress;
        DWORD raw = pSec[i].PointerToRawData;
        DWORD sz  = pSec[i].SizeOfRawData;
        if (rva >= va && rva < va + sz) {
            return (rva - va) + raw;
        }
    }
    return 0;
}

static BOOL _BufHasPattern(const unsigned char* pBuf, DWORD cbBuf,
                           const unsigned char* pat, DWORD cbPat,
                           DWORD* pOutOffset)
{
    if (!pBuf || !pat || cbBuf == 0 || cbPat == 0) return FALSE;
    if (cbPat > cbBuf) return FALSE;
    for (DWORD i = 0; i <= cbBuf - cbPat; i++) {
        if (pBuf[i] == pat[0] && memcmp(pBuf + i, pat, cbPat) == 0) {
            if (pOutOffset) *pOutOffset = i;
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================== VERSION ============================== */

__declspec(dllexport) DWORD APIENTRY YShield_Version(DWORD* pOutMajor,
                                                    DWORD* pOutMinor,
                                                    DWORD* pOutPatch)
{
    if (pOutMajor) *pOutMajor = 1;
    if (pOutMinor) *pOutMinor = 0;
    if (pOutPatch) *pOutPatch = 0;
    return Y_STATUS_CLEAN;
}

/* ============================== CORE API ============================== */

__declspec(dllexport) DWORD APIENTRY Internal_ElevatePrivileges(void) {
    return Y_ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD APIENTRY Internal_InitializeSelfDefense(void) {
    return Y_ERROR_NOT_SUPPORTED;
}

__declspec(dllexport) DWORD APIENTRY Scan_RemoteProcessMemory(
    DWORD dwPid, const unsigned char* pPattern, DWORD dwLen)
{
    (void)pPattern; (void)dwLen;
    if (dwPid != GetCurrentProcessId()) return Y_ERROR_NOT_SUPPORTED;
    return Y_ERROR_NOT_SUPPORTED;
}

/* ============================== ENTROPY ============================== */

__declspec(dllexport) DWORD APIENTRY Utility_CalculateEntropy(
    const unsigned char* pData, DWORD dwLen)
{
    if (!pData || dwLen == 0) return 0;
    DWORD freq[256];
    ZeroMemory(freq, sizeof(freq));
    for (DWORD i = 0; i < dwLen; i++) freq[pData[i]]++;

    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            double p = (double)freq[i] / (double)dwLen;
            ent -= p * log2(p);
        }
    }
    return (DWORD)(ent * 100.0);
}

__declspec(dllexport) DWORD APIENTRY Utility_AnalyzeSectionEntropy(
    const char* szPath, Y_SECTION_ENTROPY* pOut, DWORD dwMaxSections)
{
    if (!szPath || !pOut || dwMaxSections == 0) return 0;
    ZeroMemory(pOut, sizeof(Y_SECTION_ENTROPY) * (size_t)dwMaxSections);

    HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    DWORD outCount = 0;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != Y_PE_MAGIC_DOS) __leave;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
        if (nt->Signature != Y_PE_MAGIC_NT) __leave;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) __leave;

        WORD n = nt->FileHeader.NumberOfSections;
        if (n > (WORD)dwMaxSections) n = (WORD)dwMaxSections;
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

        for (WORD i = 0; i < n; i++) {
            DWORD off = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (sz == 0) continue;
            if (off >= fileSize) continue;
            if (off + sz > fileSize) continue;

            Y_SECTION_ENTROPY* o = &pOut[outCount++];
            ZeroMemory(o, sizeof(*o));
            memcpy(o->szName, sec[i].Name, 8);
            o->szName[8] = '\0';
            o->dwRawSize  = sz;
            o->dwVirtSize = sec[i].Misc.VirtualSize;
            o->dwChars    = sec[i].Characteristics;
            o->dwEntropy  = Utility_CalculateEntropy(base + off, sz);
            o->bSuspicious = (o->dwEntropy >= Y_ENTROPY_THRESHOLD_WARN);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        outCount = 0;
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return outCount;
}

/* ============================== PE STRUCTURE ============================== */

__declspec(dllexport) DWORD APIENTRY Scan_PEStructureForensics(
    const char* szPath, Y_PE_METADATA* pMeta)
{
    if (!szPath || !pMeta) return Y_ERROR_INVALID_IMAGE;
    ZeroMemory(pMeta, sizeof(*pMeta));

    HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return Y_ERROR_OPEN_PROCESS;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return Y_ERROR_MEMORY_READ; }

    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return Y_ERROR_MEMORY_READ; }

    DWORD res = Y_STATUS_CLEAN;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != Y_PE_MAGIC_DOS) { res = Y_ERROR_INVALID_IMAGE; __leave; }
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
        if (nt->Signature != Y_PE_MAGIC_NT) { res = Y_ERROR_INVALID_IMAGE; __leave; }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { res = Y_ERROR_INVALID_IMAGE; __leave; }

        pMeta->dwEntryPoint   = nt->OptionalHeader.AddressOfEntryPoint;
        pMeta->dwImageBase    = (DWORD)(nt->OptionalHeader.ImageBase & 0xFFFFFFFFu);
        pMeta->dwSizeOfImage  = nt->OptionalHeader.SizeOfImage;
        pMeta->dwSectionCount = nt->FileHeader.NumberOfSections;
        pMeta->bIsDll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

        IMAGE_DATA_DIRECTORY clr = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        pMeta->bIsDotNet = (clr.VirtualAddress && clr.Size) ? TRUE : FALSE;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        BOOL hasWX = FALSE;
        DWORD bestRaw = 0;
        char bestName[16] = {0};

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD ch = sec[i].Characteristics;
            BOOL w = (ch & IMAGE_SCN_MEM_WRITE) != 0;
            BOOL x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            if (w && x) hasWX = TRUE;

            if (sec[i].SizeOfRawData > bestRaw) {
                bestRaw = sec[i].SizeOfRawData;
                ZeroMemory(bestName, sizeof(bestName));
                memcpy(bestName, sec[i].Name, 8);
            }
        }
        pMeta->bHasWriteExec = hasWX;
        _SafeStrCopy(pMeta->szPrimarySection, sizeof(pMeta->szPrimarySection), bestName);

        DWORD sample = fileSize;
        if (sample > 2u * 1024u * 1024u) sample = 2u * 1024u * 1024u;
        if (sample) pMeta->dwEntropy = Utility_CalculateEntropy(base, sample);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        res = Y_ERROR_INVALID_IMAGE;
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return res;
}

/* ============================== DISK SCAN ============================== */

__declspec(dllexport) DWORD APIENTRY Scan_RecursiveDiskIO(
    const char* szPath, const unsigned char* pPattern, DWORD dwLen)
{
    if (!szPath || !pPattern || dwLen == 0) return Y_ERROR_INVALID_IMAGE;

    DWORD attr = GetFileAttributesA(szPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return Y_ERROR_INVALID_IMAGE;

    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return Y_ERROR_OPEN_PROCESS;

        unsigned char* buf = (unsigned char*)malloc(Y_IO_BUFFER_SIZE);
        if (!buf) { CloseHandle(hFile); return Y_ERROR_MEMORY_READ; }

        DWORD res = Y_STATUS_CLEAN;
        DWORD rd = 0;
        while (ReadFile(hFile, buf, Y_IO_BUFFER_SIZE, &rd, NULL) && rd > 0) {
            if (_BufHasPattern(buf, rd, pPattern, dwLen, NULL)) { res = Y_STATUS_THREAT; break; }
        }
        free(buf);
        CloseHandle(hFile);
        return res;
    }

    char search[MAX_PATH];
    _snprintf(search, sizeof(search), "%s\\*", szPath);
    search[sizeof(search) - 1] = '\0';

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return Y_STATUS_CLEAN;

    DWORD finalRes = Y_STATUS_CLEAN;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char child[MAX_PATH];
        _snprintf(child, sizeof(child), "%s\\%s", szPath, fd.cFileName);
        child[sizeof(child) - 1] = '\0';
        DWORD r = Scan_RecursiveDiskIO(child, pPattern, dwLen);
        if (r == Y_STATUS_THREAT) { finalRes = Y_STATUS_THREAT; break; }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return finalRes;
}

/* ============================== SIGDB ============================== */

static Y_SIGNATURE g_SigTable[Y_MAX_SIGNATURES];
static DWORD g_SigCount = 0;
static CRITICAL_SECTION g_SigLock;
static BOOL g_SigInit = FALSE;

static const Y_SIGNATURE g_DefaultSigs[] = {
    { "Test/EICAR-Substring",
      { 'E','I','C','A','R','-','S','T','A','N','D','A','R','D','-','A','N','T','I','V','I','R','U','S','-','T','E','S','T','-','F','I','L','E' },
      34, Y_SEV_HIGH },
    { "Packer/UPX-Header", { 'U','P','X','!' }, 4, Y_SEV_MEDIUM },
};

__declspec(dllexport) DWORD APIENTRY Sigdb_Initialize(void) {
    if (g_SigInit) return Y_STATUS_CLEAN;
    InitializeCriticalSection(&g_SigLock);
    EnterCriticalSection(&g_SigLock);

    DWORD n = (DWORD)(sizeof(g_DefaultSigs) / sizeof(g_DefaultSigs[0]));
    if (n > Y_MAX_SIGNATURES) n = Y_MAX_SIGNATURES;
    memcpy(g_SigTable, g_DefaultSigs, (size_t)n * sizeof(Y_SIGNATURE));
    g_SigCount = n;
    g_SigInit = TRUE;

    LeaveCriticalSection(&g_SigLock);
    return Y_STATUS_CLEAN;
}

__declspec(dllexport) DWORD APIENTRY Sigdb_RegisterSignature(
    const char* szName, const unsigned char* pPattern, DWORD dwLen, DWORD dwSeverity)
{
    if (!g_SigInit) return Y_ERROR_NOT_SUPPORTED;
    if (!szName || !pPattern || dwLen == 0 || dwLen > Y_MAX_SIG_LEN) return Y_ERROR_INVALID_IMAGE;

    EnterCriticalSection(&g_SigLock);
    if (g_SigCount >= Y_MAX_SIGNATURES) { LeaveCriticalSection(&g_SigLock); return Y_ERROR_SIGDB_FULL; }

    Y_SIGNATURE* e = &g_SigTable[g_SigCount++];
    ZeroMemory(e, sizeof(*e));
    _SafeStrCopy(e->szName, sizeof(e->szName), szName);
    memcpy(e->pPattern, pPattern, dwLen);
    e->dwLen = dwLen;
    e->dwSeverity = dwSeverity;

    LeaveCriticalSection(&g_SigLock);
    return Y_STATUS_CLEAN;
}

__declspec(dllexport) DWORD APIENTRY Sigdb_ScanBuffer(
    const unsigned char* pData, DWORD dwLen, Y_MATCH_RESULT* pMatchOut)
{
    if (!g_SigInit || !pData || dwLen == 0) return Y_STATUS_CLEAN;
    EnterCriticalSection(&g_SigLock);
    for (DWORD s = 0; s < g_SigCount; s++) {
        const Y_SIGNATURE* sig = &g_SigTable[s];
        DWORD off = 0;
        if (_BufHasPattern(pData, dwLen, sig->pPattern, sig->dwLen, &off)) {
            if (pMatchOut) {
                ZeroMemory(pMatchOut, sizeof(*pMatchOut));
                _SafeStrCopy(pMatchOut->szSigName, sizeof(pMatchOut->szSigName), sig->szName);
                pMatchOut->dwOffset = off;
                pMatchOut->dwSeverity = sig->dwSeverity;
                pMatchOut->dwSigIndex = s;
            }
            LeaveCriticalSection(&g_SigLock);
            return Y_STATUS_THREAT;
        }
    }
    LeaveCriticalSection(&g_SigLock);
    return Y_STATUS_CLEAN;
}

/* ============================== IMPORT FORENSICS ============================== */

static const struct { const char* api; DWORD score; const char* why; } g_Watch[] = {
    { "VirtualProtect", 6, "Memory protection changes" },
    { "WinExec", 10, "Process spawn primitive" },
    { "ShellExecuteA", 10, "Process spawn primitive" },
    { "ShellExecuteW", 10, "Process spawn primitive" },
    { "URLDownloadToFileA", 12, "Downloader primitive" },
    { "InternetOpenA", 6, "WinINet usage" },
    { "HttpSendRequestA", 8, "HTTP request primitive" },
};

__declspec(dllexport) DWORD APIENTRY Scan_ImportTableForensics(
    const char* szPath, Y_IMPORT_REPORT* pReport)
{
    if (!szPath || !pReport) return Y_ERROR_INVALID_IMAGE;
    ZeroMemory(pReport, sizeof(*pReport));

    HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return Y_ERROR_OPEN_PROCESS;
    DWORD fileSize = GetFileSize(hFile, NULL);

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return Y_ERROR_MEMORY_READ; }
    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return Y_ERROR_MEMORY_READ; }

    DWORD res = Y_STATUS_CLEAN;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != Y_PE_MAGIC_DOS) { res = Y_ERROR_INVALID_IMAGE; __leave; }
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
        if (nt->Signature != Y_PE_MAGIC_NT) { res = Y_ERROR_INVALID_IMAGE; __leave; }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { res = Y_ERROR_INVALID_IMAGE; __leave; }

        IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) { res = Y_STATUS_CLEAN; __leave; }

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        DWORD nSec = nt->FileHeader.NumberOfSections;
        DWORD impOff = _RvaToOffset(dir.VirtualAddress, sec, nSec);
        if (!impOff || impOff >= fileSize) { res = Y_STATUS_CLEAN; __leave; }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impOff);
        while (imp->Name && pReport->dwDllCount < Y_MAX_IMPORT_DLLS) {
            DWORD nameOff = _RvaToOffset(imp->Name, sec, nSec);
            if (!nameOff || nameOff >= fileSize) { imp++; continue; }
            const char* dll = (const char*)(base + nameOff);
            _SafeStrCopy(pReport->szDlls[pReport->dwDllCount++], Y_MAX_DLL_NAME, dll);

            DWORD thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            DWORD thunkOff = _RvaToOffset(thunkRva, sec, nSec);
            if (!thunkOff || thunkOff >= fileSize) { imp++; continue; }

            IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(base + thunkOff);
            while (thunk->u1.AddressOfData) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    DWORD ibnOff = _RvaToOffset((DWORD)(thunk->u1.AddressOfData & 0xFFFFFFFFu), sec, nSec);
                    if (ibnOff && ibnOff + 2 < fileSize) {
                        const char* api = (const char*)(base + ibnOff + 2);
                        pReport->dwTotalImports++;
                        for (DWORD w = 0; w < (DWORD)(sizeof(g_Watch) / sizeof(g_Watch[0])); w++) {
                            if (_stricmp(api, g_Watch[w].api) == 0) {
                                pReport->dwThreatScore += g_Watch[w].score;
                                if (pReport->dwFlaggedCount < Y_MAX_FLAGGED_IMPORTS) {
                                    Y_FLAGGED_IMPORT* f = &pReport->flagged[pReport->dwFlaggedCount++];
                                    _SafeStrCopy(f->szApi, sizeof(f->szApi), api);
                                    _SafeStrCopy(f->szDll, sizeof(f->szDll), dll);
                                    _SafeStrCopy(f->szReason, sizeof(f->szReason), g_Watch[w].why);
                                    f->dwScore = g_Watch[w].score;
                                }
                                break;
                            }
                        }
                    }
                }
                thunk++;
            }
            imp++;
        }

        if (pReport->dwThreatScore >= Y_IMPORT_THREAT_THRESHOLD) res = Y_STATUS_THREAT;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        res = Y_ERROR_MEMORY_READ;
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return res;
}

/* ============================== COMPOSITE ============================== */

__declspec(dllexport) DWORD APIENTRY Heuristic_CompositeScan(
    const char* szPath, Y_THREAT_REPORT* pReport)
{
    if (!szPath || !pReport) return Y_ERROR_INVALID_IMAGE;
    ZeroMemory(pReport, sizeof(*pReport));
    _SafeStrCopy(pReport->szFilePath, sizeof(pReport->szFilePath), szPath);
    pReport->dwTimestamp = (DWORD)time(NULL);

    DWORD r = Scan_PEStructureForensics(szPath, &pReport->pe);
    if (r & 0x80000000u) { pReport->dwFinalVerdict = r; return r; }

    if (pReport->pe.bIsDotNet) pReport->dwFlags |= Y_FLAG_DOTNET;
    if (pReport->pe.bHasWriteExec) { pReport->dwScore += 30; pReport->dwFlags |= Y_FLAG_WX_SECTION; }
    if (!pReport->pe.bIsDll && pReport->pe.dwEntryPoint == 0) { pReport->dwScore += 10; pReport->dwFlags |= Y_FLAG_ZERO_EP; }

    Y_SECTION_ENTROPY secs[Y_MAX_SECTIONS];
    ZeroMemory(secs, sizeof(secs));
    DWORD nSec = Utility_AnalyzeSectionEntropy(szPath, secs, Y_MAX_SECTIONS);
    pReport->dwSectionCount = nSec;
    DWORD packed = 0;
    for (DWORD i = 0; i < nSec; i++) {
        pReport->sections[i] = secs[i];
        if (secs[i].dwEntropy >= Y_ENTROPY_THRESHOLD_PACKED) { pReport->dwScore += 25; pReport->dwFlags |= Y_FLAG_HIGH_ENTROPY; packed++; }
        else if (secs[i].dwEntropy >= Y_ENTROPY_THRESHOLD_WARN) { pReport->dwScore += 10; pReport->dwFlags |= Y_FLAG_HIGH_ENTROPY; }
    }
    if (packed >= 2) pReport->dwScore += 20;

    Scan_ImportTableForensics(szPath, &pReport->imports);
    if (pReport->imports.dwFlaggedCount) { pReport->dwScore += pReport->imports.dwThreatScore; pReport->dwFlags |= Y_FLAG_SUSPICIOUS_IMPORTS; }
    if (!pReport->pe.bIsDll && pReport->imports.dwTotalImports > 0 && pReport->imports.dwTotalImports < 5) { pReport->dwScore += 20; pReport->dwFlags |= Y_FLAG_MINIMAL_IMPORTS; }

    if (g_SigInit) {
        HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fs = GetFileSize(hFile, NULL);
            if (fs > 0 && fs <= Y_MAX_SIGDB_SCAN_SIZE) {
                unsigned char* buf = (unsigned char*)malloc(fs);
                if (buf) {
                    DWORD rd = 0;
                    if (ReadFile(hFile, buf, fs, &rd, NULL) && rd) {
                        Y_MATCH_RESULT mr;
                        ZeroMemory(&mr, sizeof(mr));
                        if (Sigdb_ScanBuffer(buf, rd, &mr) == Y_STATUS_THREAT) {
                            pReport->dwFlags |= Y_FLAG_SIGDB_HIT;
                            pReport->sigMatch = mr;
                            pReport->dwScore += 50 + mr.dwSeverity * 10;
                        }
                    }
                    free(buf);
                }
            }
            CloseHandle(hFile);
        }
    }

    if ((pReport->dwFlags & Y_FLAG_SIGDB_HIT) || pReport->dwScore >= Y_SCORE_THREAT) pReport->dwFinalVerdict = Y_STATUS_THREAT;
    else if (pReport->dwScore >= Y_SCORE_SUSPICIOUS) pReport->dwFinalVerdict = Y_STATUS_SUSPICIOUS;
    else pReport->dwFinalVerdict = Y_STATUS_CLEAN;

    return pReport->dwFinalVerdict;
}

/* ============================== SERIALIZER ============================== */

__declspec(dllexport) DWORD APIENTRY Report_Serialize(
    const Y_THREAT_REPORT* pReport, char* pOutBuf, DWORD dwBufLen)
{
    if (!pReport || !pOutBuf || dwBufLen == 0) return Y_ERROR_INVALID_IMAGE;

    static const char* verdicts[] = { "CLEAN", "THREAT", "SUSPICIOUS" };
    static const char* sev[] = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    const char* verdict = (pReport->dwFinalVerdict <= 2) ? verdicts[pReport->dwFinalVerdict] : "ERROR";

    time_t ts = (time_t)pReport->dwTimestamp;
    char tbuf[32] = {0};
    struct tm* ptm = localtime(&ts);
    if (ptm) strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", ptm);

    int w = _snprintf(pOutBuf, (size_t)dwBufLen,
        "===================================================\n"
        "  Y-SHIELD DEFENSIVE REPORT\n"
        "===================================================\n"
        "  File     : %s\n"
        "  Scanned  : %s\n"
        "  Score    : %lu / 255\n"
        "  Verdict  : %s\n"
        "  Flags    : 0x%08lX\n"
        "---------------------------------------------------\n"
        "  PE Metadata\n"
        "---------------------------------------------------\n"
        "  EntryPoint : 0x%08lX\n"
        "  Sections   : %lu\n"
        "  ImageSize  : %lu bytes\n"
        "  IsDLL      : %s\n"
        "  IsDotNet   : %s\n"
        "  W+X Secs   : %s\n"
        "  FileEntropy: %lu.%02lu\n"
        "---------------------------------------------------\n"
        "  Section Entropy (%lu sections)\n"
        "---------------------------------------------------\n",
        pReport->szFilePath, tbuf,
        pReport->dwScore, verdict, pReport->dwFlags,
        pReport->pe.dwEntryPoint,
        pReport->pe.dwSectionCount,
        pReport->pe.dwSizeOfImage,
        pReport->pe.bIsDll ? "YES" : "NO",
        pReport->pe.bIsDotNet ? "YES" : "NO",
        pReport->pe.bHasWriteExec ? "YES" : "NO",
        pReport->pe.dwEntropy / 100, pReport->pe.dwEntropy % 100,
        pReport->dwSectionCount
    );
    if (w < 0) return Y_ERROR_BUFFER_TOO_SMALL;

    for (DWORD i = 0; i < pReport->dwSectionCount && w < (int)dwBufLen - 1; i++) {
        const Y_SECTION_ENTROPY* s = &pReport->sections[i];
        w += _snprintf(pOutBuf + w, (size_t)dwBufLen - (size_t)w,
            "  [%-8s] Entropy: %lu.%02lu  RawSz: %-8lu  %s\n",
            s->szName,
            s->dwEntropy / 100, s->dwEntropy % 100,
            s->dwRawSize,
            s->bSuspicious ? "<< HIGH" : "");
    }

    w += _snprintf(pOutBuf + w, (size_t)dwBufLen - (size_t)w,
        "---------------------------------------------------\n"
        "  Import Analysis: %lu DLLs | %lu APIs | Score: %lu\n"
        "---------------------------------------------------\n",
        pReport->imports.dwDllCount,
        pReport->imports.dwTotalImports,
        pReport->imports.dwThreatScore
    );

    for (DWORD i = 0; i < pReport->imports.dwFlaggedCount && w < (int)dwBufLen - 1; i++) {
        const Y_FLAGGED_IMPORT* f = &pReport->imports.flagged[i];
        w += _snprintf(pOutBuf + w, (size_t)dwBufLen - (size_t)w,
            "  [+%02lu] %s!%s — %s\n",
            f->dwScore, f->szDll, f->szApi, f->szReason);
    }

    if (pReport->dwFlags & Y_FLAG_SIGDB_HIT) {
        const char* s = (pReport->sigMatch.dwSeverity < 5) ? sev[pReport->sigMatch.dwSeverity] : "?";
        w += _snprintf(pOutBuf + w, (size_t)dwBufLen - (size_t)w,
            "---------------------------------------------------\n"
            "  SIGNATURE HIT\n"
            "---------------------------------------------------\n"
            "  Name     : %s\n"
            "  Offset   : 0x%08lX\n"
            "  Severity : %s\n",
            pReport->sigMatch.szSigName,
            pReport->sigMatch.dwOffset,
            s);
    }

    w += _snprintf(pOutBuf + w, (size_t)dwBufLen - (size_t)w,
        "===================================================\n"
        "  FINAL VERDICT: %-11s  (Composite Score: %lu)\n"
        "===================================================\n",
        verdict, pReport->dwScore);

    if (w < 0) return Y_ERROR_BUFFER_TOO_SMALL;
    return (DWORD)w;
}

