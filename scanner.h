#ifndef Y_SHIELD_SCANNER_H
#define Y_SHIELD_SCANNER_H

/* * Y-SHIELD DEFENSIVE SCANNER ENGINE
 * FILE: scanner.h
 * ARCHITECTURE: WINDOWS x64 (PE32+)
 * CREATOR - YOAD KOCHAVI
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winnt.h>
#include <stdio.h>

/* ========================== GCC/MinGW COMPATIBILITY ========================== */
#ifdef __GNUC__
  #define _vsnprintf vsnprintf
  #define _snprintf  snprintf
  #define __try      for(int _once = 1; _once; _once = 0)
  #define __except(x) if(0)
  #define __leave    break 
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================== CONSTANTS ============================== */
#define Y_MAX_SIG_LEN             1024
#define Y_IO_BUFFER_SIZE          (4u * 1024u * 1024u) 
#define Y_MAX_SECTIONS            256
#define Y_MAX_LOG_MESSAGE         2048
#define Y_PE_MAGIC_DOS            0x5A4D      
#define Y_PE_MAGIC_NT             0x00004550  
#define Y_MAX_SIGNATURES          512
#define Y_MAX_SIG_NAME            64
#define Y_MAX_IMPORT_DLLS         128
#define Y_MAX_DLL_NAME            64
#define Y_MAX_FLAGGED_IMPORTS     64
#define Y_MAX_SIGDB_SCAN_SIZE     (32u * 1024u * 1024u) 
#define Y_ENTROPY_THRESHOLD_WARN    680u  
#define Y_ENTROPY_THRESHOLD_PACKED  740u  
#define Y_SCORE_SUSPICIOUS         40u
#define Y_SCORE_THREAT             80u
#define Y_IMPORT_THREAT_THRESHOLD  30u
#define Y_SEV_INFO      0u
#define Y_SEV_LOW       1u
#define Y_SEV_MEDIUM    2u
#define Y_SEV_HIGH      3u
#define Y_SEV_CRITICAL  4u

/* Heuristic flags */
#define Y_FLAG_WX_SECTION           0x00000001u
#define Y_FLAG_HIGH_ENTROPY         0x00000002u
#define Y_FLAG_SUSPICIOUS_IMPORTS   0x00000004u
#define Y_FLAG_SIGDB_HIT            0x00000008u
#define Y_FLAG_ZERO_EP              0x00000010u
#define Y_FLAG_MINIMAL_IMPORTS      0x00000020u
#define Y_FLAG_DOTNET               0x00000040u
#define Y_FLAG_IMPORT_DIRECTORY     0x00000080u

/* Status codes */
#define Y_STATUS_CLEAN             0x00000000u
#define Y_STATUS_THREAT            0x00000001u
#define Y_STATUS_SUSPICIOUS        0x00000002u
#define Y_ERROR_PRIVILEGE          0x80000001u
#define Y_ERROR_OPEN_PROCESS       0x80000002u
#define Y_ERROR_MEMORY_READ        0x80000003u
#define Y_ERROR_INVALID_IMAGE      0x80000004u
#define Y_ERROR_SIGDB_FULL         0x80000005u
#define Y_ERROR_BUFFER_TOO_SMALL   0x80000006u
#define Y_ERROR_NOT_SUPPORTED      0x80000007u
#define Y_ERROR_IO                 0x80000008u

/* ============================== STRUCTURES ============================== */
typedef struct _Y_PE_METADATA {
    DWORD dwEntryPoint;
    DWORD dwImageBase;
    DWORD dwSizeOfImage;
    DWORD dwSectionCount;
    BOOL  bHasWriteExec;
    BOOL  bIsDotNet;
    BOOL  bIsDll;
    char  szPrimarySection[16];
    DWORD dwEntropy;
} Y_PE_METADATA;

typedef struct _Y_SECTION_ENTROPY {
    char  szName[10];
    DWORD dwEntropy;
    DWORD dwRawSize;
    DWORD dwVirtSize;
    DWORD dwChars;
    BOOL  bSuspicious;
} Y_SECTION_ENTROPY;

typedef struct _Y_SIGNATURE {
    char          szName[Y_MAX_SIG_NAME];
    unsigned char pPattern[Y_MAX_SIG_LEN];
    DWORD         dwLen;
    DWORD         dwSeverity;
} Y_SIGNATURE;

typedef struct _Y_MATCH_RESULT {
    char  szSigName[Y_MAX_SIG_NAME];
    DWORD dwOffset;
    DWORD dwSeverity;
    DWORD dwSigIndex;
} Y_MATCH_RESULT;

typedef struct _Y_FLAGGED_IMPORT {
    char  szApi[64];
    char  szDll[64];
    char  szReason[128];
    DWORD dwScore;
} Y_FLAGGED_IMPORT;

typedef struct _Y_IMPORT_REPORT {
    char  szDlls[Y_MAX_IMPORT_DLLS][Y_MAX_DLL_NAME];
    DWORD dwDllCount;
    DWORD dwTotalImports;
    DWORD dwThreatScore;
    DWORD dwFlaggedCount;
    Y_FLAGGED_IMPORT flagged[Y_MAX_FLAGGED_IMPORTS];
} Y_IMPORT_REPORT;

typedef struct _Y_THREAT_REPORT {
    char             szFilePath[MAX_PATH];
    DWORD            dwTimestamp;
    DWORD            dwScore;
    DWORD            dwFlags;
    DWORD            dwFinalVerdict;
    DWORD            dwSectionCount;
    Y_PE_METADATA     pe;
    Y_SECTION_ENTROPY sections[Y_MAX_SECTIONS];
    Y_IMPORT_REPORT   imports;
    Y_MATCH_RESULT     sigMatch;
} Y_THREAT_REPORT;

/* ============================== EXPORTS ============================== */
#ifndef Y_API
#define Y_API __declspec(dllexport) DWORD APIENTRY
#endif

Y_API YShield_Version(DWORD* pOutMajor, DWORD* pOutMinor, DWORD* pOutPatch);
Y_API Internal_ElevatePrivileges(void);
Y_API Internal_InitializeSelfDefense(void);
Y_API Scan_RemoteProcessMemory(DWORD dwPid, const unsigned char* pPattern, DWORD dwLen);
Y_API Scan_PEStructureForensics(const char* szPath, Y_PE_METADATA* pMeta);
Y_API Scan_RecursiveDiskIO(const char* szPath, const unsigned char* pPattern, DWORD dwLen);
Y_API Utility_CalculateEntropy(const unsigned char* pData, DWORD dwLen);
Y_API Utility_AnalyzeSectionEntropy(const char* szPath, Y_SECTION_ENTROPY* pOut, DWORD dwMaxSections);
Y_API Sigdb_Initialize(void);
Y_API Sigdb_RegisterSignature(const char* szName, const unsigned char* pPattern, DWORD dwLen, DWORD dwSeverity);
Y_API Sigdb_ScanBuffer(const unsigned char* pData, DWORD dwLen, Y_MATCH_RESULT* pMatchOut);
Y_API Scan_ImportTableForensics(const char* szPath, Y_IMPORT_REPORT* pReport);
Y_API Heuristic_CompositeScan(const char* szPath, Y_THREAT_REPORT* pReport);
Y_API Report_Serialize(const Y_THREAT_REPORT* pReport, char* pOutBuf, DWORD dwBufLen);

#ifdef __cplusplus
}
#endif

#endif /* Y_SHIELD_SCANNER_H */