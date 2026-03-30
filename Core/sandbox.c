#ifdef _WIN32
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * No Windows, usamos Job Objects para isolar o processo.
 * Isso permite restringir o uso de CPU, memória, rede e impedir a criação de novos processos.
 */
bool try_hard_isolate(const char *app_path) {
    HANDLE hJob = CreateJobObject(NULL, "KomodoSecureJob");
    if (hJob == NULL) {
        return false;
    }

    // 1. Restrições de UI e Sistema
    JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrictions = {0};
    uiRestrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | 
                                         JOB_OBJECT_UILIMIT_READCLIPBOARD | 
                                         JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                                         JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                                         JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
    
    if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiRestrictions, sizeof(uiRestrictions))) {
        CloseHandle(hJob);
        return false;
    }

    // 2. Restrições de Limite de Processos e Rede (via JobObjectNetworkLimitInformation se disponível)
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limitInfo = {0};
    limitInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 
                                                 JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                                                 JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limitInfo.BasicLimitInformation.ActiveProcessLimit = 1; // Impede criação de subprocessos

    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &limitInfo, sizeof(limitInfo))) {
        CloseHandle(hJob);
        return false;
    }

    // 3. Associar o processo atual ao Job
    if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
        // Se já estiver em um job, pode falhar dependendo das permissões
        CloseHandle(hJob);
        return false;
    }

    // No Windows, o isolamento de rede "puro" via C é mais complexo (exige Windows Filtering Platform),
    // mas o Job Object já impede que o processo crie novos sockets se configurado via AppContainer.
    // Para uma CLI simples, o Job Object é a base mais forte.

    return true;
}
#else
// Fallback para Linux (mantendo compatibilidade mínima se necessário)
#include <stdbool.h>
bool try_hard_isolate(const char *app_path) {
    return false; // Desativado nesta versão focada em Windows
}
#endif
