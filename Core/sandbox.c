#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <userenv.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

// Mitigation policies (valores corretos do SDK)
#define PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE                  0x00000001ULL
#define PROCESS_CREATION_MITIGATION_POLICY_ASLR_FORCE_RELOCATE_IMAGES_ALWAYS_ON 0x00000100ULL
#define PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON      0x00010000ULL
#define PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON 0x0000000000020000ULL


bool setup_app_container(const char* container_name, PSID* pSid) {
    wchar_t wName[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wName, MAX_PATH) == 0)
        return false;

    HRESULT hr = CreateAppContainerProfile(wName, wName, wName, NULL, 0, pSid);
    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            hr = DeriveAppContainerSidFromAppContainerName(wName, pSid);
        }
        if (FAILED(hr)) {
            printf("Erro Create/Derive AppContainer: 0x%08X\n", hr);
            return false;
        }
    }
    return true;
}

bool create_restricted_process(const char* app_path, PSID appContainerSid) {
    HANDLE hToken = NULL;
    HANDLE hRestrictedToken = NULL;
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        printf("Erro OpenProcessToken: %lu\n", GetLastError());
        return false;
    }

    // Cria token restrito (opcional com AppContainer, mas reforça)
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestrictedToken)) {
        printf("Erro CreateRestrictedToken: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    // (Opcional) Força Low Integrity - AppContainer já força Low/Untrusted na maioria dos casos
    /*
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pLowSid = NULL;
    if (AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_LOW_RID, 0,0,0,0,0,0,0, &pLowSid)) {
        TOKEN_MANDATORY_LABEL tml = {0};
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pLowSid;
        SetTokenInformation(hRestrictedToken, TokenIntegrityLevel, &tml,
                            sizeof(tml) + GetLengthSid(pLowSid));
        FreeSid(pLowSid);
    }
    */

    // ==================== Atributos para criação ====================
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &attrSize);

    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!si.lpAttributeList || !InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attrSize)) {
        printf("Erro InitializeProcThreadAttributeList: %lu\n", GetLastError());
        CloseHandle(hRestrictedToken);
        return false;
    }

    // 1. SECURITY_CAPABILITIES → necessário para AppContainer
    SECURITY_CAPABILITIES sc = {0};
    sc.AppContainerSid = appContainerSid;
    sc.Capabilities = NULL;
    sc.CapabilityCount = 0;

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &sc, sizeof(sc), NULL, NULL)) {
        printf("Erro UpdateProcThreadAttribute SECURITY_CAPABILITIES: %lu\n", GetLastError());
        goto cleanup;
    }

    // 2. Mitigation Policy (DEP + ASLR + Strict Handle)
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
                     PROCESS_CREATION_MITIGATION_POLICY_ASLR_FORCE_RELOCATE_IMAGES_ALWAYS_ON |
                     PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &policy, sizeof(policy), NULL, NULL)) {
        printf("Erro UpdateProcThreadAttribute MITIGATION_POLICY: %lu\n", GetLastError());
        goto cleanup;
    }

    // Desktop isolado (cuidado: se não existir, pode falhar)
    // si.StartupInfo.lpDesktop = L"KomodoSandboxDesktop";

    wchar_t wAppPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, app_path, -1, wAppPath, MAX_PATH);

    // ==================== Cria o processo ====================
    BOOL success = CreateProcessAsUser(
        hRestrictedToken,
        wAppPath,           // lpApplicationName
        NULL,               // lpCommandLine
        NULL, NULL,         // lpProcessAttributes / lpThreadAttributes
        FALSE,              // bInheritHandles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,               // lpEnvironment
        NULL,               // lpCurrentDirectory
        &si.StartupInfo,
        &pi
    );

    if (!success) {
        printf("Erro CreateProcessAsUser: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("Processo sandbox criado com sucesso! PID: %lu\n", pi.dwProcessId);

    // ==================== Job Object (mata processo ao fechar) ====================
    HANDLE hJob = CreateJobObject(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(hJob, pi.hProcess);
        // Não feche o hJob aqui se quiser manter o job vivo
    }

cleanup:
    if (si.lpAttributeList) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    }
    if (hRestrictedToken) CloseHandle(hRestrictedToken);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);

    return success;
}

bool try_hard_isolate(const char* app_path) {
    PSID appContainerSid = NULL;
    bool result = false;

    if (setup_app_container("KomodoSecureSandbox", &appContainerSid)) {
        result = create_restricted_process(app_path, appContainerSid);
    }

    if (appContainerSid)
        FreeSid(appContainerSid);

    return result;
}