#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <userenv.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

// Definindo os valores manualmente para compatibilidade total
#define K_DEP_ENABLE      0x0000000000000001ULL
#define K_ASLR_ALWAYS_ON  0x0000000000000004ULL
#define K_STRICT_HANDLE   0x0000000000000010ULL // O que estava dando erro
#define K_NO_REMOTE_LOAD  (1ULL << 52)

bool setup_app_container(const char* container_name, PSID* pSid) {
    wchar_t wName[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wName, MAX_PATH) == 0) return false;

    HRESULT hr = CreateAppContainerProfile(wName, wName, wName, NULL, 0, pSid);
    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            hr = DeriveAppContainerSidFromAppContainerName(wName, pSid);
        }
        if (FAILED(hr)) return false;
    }
    return true;
}

bool create_restricted_process(const char* app_path, PSID appContainerSid) {
    HANDLE hToken = NULL;
    HANDLE hRestrictedToken = NULL;
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) return false;

    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestrictedToken)) {
        CloseHandle(hToken);
        return false;
    }

    // Nível Untrusted (Integridade mínima)
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pUntrustedSid = NULL;
    if (AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0, 0, 0, &pUntrustedSid)) {
        TOKEN_MANDATORY_LABEL tml = {0};
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pUntrustedSid;
        SetTokenInformation(hRestrictedToken, TokenIntegrityLevel, &tml, (DWORD)(sizeof(tml) + GetLengthSid(pUntrustedSid)));
    }

    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    
    if (!si.lpAttributeList || !InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
        return false;
    }

    // Usando os valores manuais que definimos no topo do arquivo
    DWORD64 policy = K_DEP_ENABLE | K_ASLR_ALWAYS_ON | K_STRICT_HANDLE | K_NO_REMOTE_LOAD;

    UpdateProcThreadAttribute(
        si.lpAttributeList, 
        0, 
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, 
        &policy, 
        sizeof(policy), 
        NULL, 
        NULL
    );

    // Desktop Isolado
    si.StartupInfo.lpDesktop = (LPWSTR)L"KomodoSandboxDesktop";

    wchar_t wAppPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, app_path, -1, wAppPath, MAX_PATH);

    BOOL success = CreateProcessAsUserW(
        hRestrictedToken,
        wAppPath,
        NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL, NULL,
        &si.StartupInfo,
        &pi
    );

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    if (pUntrustedSid) FreeSid(pUntrustedSid);
    CloseHandle(hRestrictedToken);
    CloseHandle(hToken);
    
    return success != 0;
}

bool try_hard_isolate(const char* app_path) {
    PSID appContainerSid = NULL;
    if (!setup_app_container("KomodoSecureSandbox", &appContainerSid)) return false;
    bool result = create_restricted_process(app_path, appContainerSid);
    if (appContainerSid) FreeSid(appContainerSid);
    return result;
}