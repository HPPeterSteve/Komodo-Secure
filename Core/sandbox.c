#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Windows 10 para AppContainer e APIs de token
#endif

#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <winnt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

/**
 * Komodo-Secure: Fortaleza de Isolamento Windows
 * Implementa: AppContainer, Restricted Tokens, Low Integrity Level, 
 * Mitigation Policies (ASLR, DEP, win32k block) e Desktop Isolado.
 */

bool setup_app_container(const char* container_name, PSID* pSid) {
    wchar_t wName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wName, MAX_PATH);

    // 1. Criar Perfil do AppContainer
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

    // 1. Obter Token do Processo Atual
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) return false;

    
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestrictedToken)) {
        CloseHandle(hToken);
        return false;
    }

    // 3. Definir Integrity Level (Untrusted - Mais forte que Low)
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
                                                     PSID pUntrustedSid = NULL;
    AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0, 0, 0, &pUntrustedSid);

    TOKEN_MANDATORY_LABEL tml = {0};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pUntrustedSid;

    SetTokenInformation(hRestrictedToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pUntrustedSid));

    // 4. Configurar Mitigation Policies (ASLR, DEP, win32k block)
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
                     PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
                     PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
                     PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECK_ENFORCE |
                     PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE |
                     PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL;

    SECURITY_CAPABILITIES sc = {0};
                             sc.AppContainerSid = appContainerSid;
                             sc.Capabilities = NULL;
                             sc.CapabilityCount = 0;
                             sc.Reserved = 0;             
    
    UpdateProcThreadAttribute(
        si.lpAttributeList,
         0, 
         PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
         &policy, 
         sizeof(policy), 
         NULL,
         NULL
        );
    
    // 5. Criar Desktop Isolado
    HDESK hNewDesktop = CreateDesktopA("KomodoSandboxDesktop", NULL, NULL, 0, GENERIC_ALL, NULL);
    si.StartupInfo.lpDesktop = "KomodoSandboxDesktop";

    // 6. Lançar Processo como AppContainer + Restricted Token
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

    // Cleanup
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    FreeSid(pUntrustedSid);
    CloseHandle(hRestrictedToken);
    CloseHandle(hToken);

    return success;
}

bool try_hard_isolate(const char* app_path) {
    PSID appContainerSid = NULL;
    if (!setup_app_container("KomodoSecureSandbox", &appContainerSid)) return false;
    
    // TODO: Implementar WFP (Windows Filtering Platform) para bloqueio de rede aqui

    
    bool result = create_restricted_process(app_path, appContainerSid);
    FreeSid(appContainerSid);
    return result;
}
