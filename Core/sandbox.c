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

#pragma comment(lib, "userenv.lib")

/**
 * Função para criar e configurar um AppContainer.
 * O AppContainer fornece isolamento de recursos por padrão.
 */
static BOOL CreateAndConfigureAppContainer(LPCWSTR appContainerName, PSID* appContainerSid) {
    HRESULT hr = CreateAppContainerProfile(
        appContainerName,
        appContainerName,
        appContainerName,
        NULL, 0,
        appContainerSid
    );

    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            if (!DeriveAppContainerSidFromAppContainerName(appContainerName, appContainerSid)) {
                return FALSE;
            }
        } else {
            return FALSE;
        }
    }
    return TRUE;
}

/**
 * Função para criar um token restrito com nível de integridade "Untrusted".
 * Isso impede que o processo interaja com objetos de maior privilégio.
 */
static BOOL CreateLowIntegrityRestrictedToken(HANDLE* restrictedToken) {
    HANDLE currentProcessToken = NULL;
    HANDLE duplicatedToken = NULL;
    PSID pIntegritySid = NULL;
    BOOL success = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken)) goto cleanup;

    if (!DuplicateTokenEx(currentProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken)) goto cleanup;

    if (!CreateRestrictedToken(duplicatedToken, 0, 0, NULL, 0, NULL, 0, NULL, restrictedToken)) goto cleanup;

    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0, 0, 0, &pIntegritySid)) goto cleanup;

    TOKEN_MANDATORY_LABEL tml = { 0 };
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pIntegritySid;

    if (!SetTokenInformation(*restrictedToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid))) goto cleanup;

    success = TRUE;

cleanup:
    if (currentProcessToken) CloseHandle(currentProcessToken);
    if (duplicatedToken) CloseHandle(duplicatedToken);
    if (pIntegritySid) FreeSid(pIntegritySid);
    return success;
}

/**
 * No Windows, usamos AppContainer + Restricted Token + Integrity Level para isolamento real.
 * Esta função agora implementa o "nível sério" de sandbox solicitado.
 */
bool try_hard_isolate(const char *app_path) {
    LPCWSTR appContainerName = L"KomodoSecureAppContainer";
    PSID appContainerSid = NULL;
    HANDLE restrictedToken = NULL;
    STARTUPINFOEXA sie = { sizeof(sie) };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeListSize = 0;
    BOOL success = FALSE;

    // 1. Configurar AppContainer
    if (!CreateAndConfigureAppContainer(appContainerName, &appContainerSid)) goto cleanup;

    // 2. Criar Token Restrito (Integrity Level: Untrusted)
    if (!CreateLowIntegrityRestrictedToken(&restrictedToken)) goto cleanup;

    // 3. Preparar atributos (AppContainer + Mitigações)
    InitializeProcThreadAttributeList(NULL, 2, 0, &attributeListSize);
    sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeListSize);
    if (!InitializeProcThreadAttributeList(sie.lpAttributeList, 2, 0, &attributeListSize)) goto cleanup;

    // Adicionar SID do AppContainer
    if (!UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &appContainerSid, sizeof(PSID), NULL, NULL)) goto cleanup;

    // Adicionar Políticas de Mitigação (DEP + ASLR + Win32k Disable)
    // Nota: Algumas flags podem não estar disponíveis em ambientes de compilação antigos, usamos valores numéricos se necessário.
    DWORD64 mitigationFlags = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE | 
                             PROCESS_CREATION_MITIGATION_POLICY_ASLR_ALWAYS_ON |
                             PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;

    if (!UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigationFlags, sizeof(mitigationFlags), NULL, NULL)) {
        // Fallback: Tentar sem Win32k disable se falhar
        mitigationFlags = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE | PROCESS_CREATION_MITIGATION_POLICY_ASLR_ALWAYS_ON;
        UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigationFlags, sizeof(mitigationFlags), NULL, NULL);
    }

    // 4. Criar o processo isolado
    // Usamos o app_path fornecido como o comando a ser executado dentro do sandbox
    success = CreateProcessAsUserA(
        restrictedToken,
        NULL,
        (LPSTR)app_path,
        NULL, NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL,
        (LPSTARTUPINFOA)&sie,
        &pi
    );

    if (success) {
        // Opcional: Poderíamos esperar aqui, mas para integração com Rust, 
        // talvez queiramos apenas disparar o processo.
        // Por enquanto, fechamos os handles para não vazar.
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

cleanup:
    if (appContainerSid) FreeSid(appContainerSid);
    if (restrictedToken) CloseHandle(restrictedToken);
    if (sie.lpAttributeList) {
        DeleteProcThreadAttributeList(sie.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
    }
    return success;
}
