#ifdef _WIN32
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "fwpuclnt.lib")

/**
 * Komodo-Secure: Bloqueio de Rede via Windows Filtering Platform (WFP)
 * Bloqueia todo o tráfego de rede para o SID do AppContainer.
 */

bool block_network_for_sid(PSID appContainerSid) {
    HANDLE hEngine = NULL;
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    // 1. Abrir o Engine do WFP
    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine) != ERROR_SUCCESS) {
        return false;
    }

    // 2. Criar Filtro de Bloqueio (IPv4 e IPv6)
    FWPM_FILTER0 filter = {0};
    filter.displayData.name = L"KomodoSecureNetworkBlock";
    filter.action.type = FWP_ACTION_BLOCK;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Camada de conexão IPv4
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xFF; // Prioridade máxima

    // Condição: Filtrar pelo SID do AppContainer
    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDITION_ALE_APP_CONTAINER_SID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_SID;
    condition.conditionValue.sid = appContainerSid;

    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;

    // 3. Adicionar Filtro IPv4
    if (FwpmFilterAdd0(hEngine, &filter, NULL, NULL) != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return false;
    }

    // 4. Adicionar Filtro IPv6
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if (FwpmFilterAdd0(hEngine, &filter, NULL, NULL) != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return false;
    }

    // O Engine permanece aberto enquanto o processo pai estiver rodando (devido ao FWPM_SESSION_FLAG_DYNAMIC)
    // Isso garante que o bloqueio seja removido quando o Komodo-Secure fechar.
    return true;
}
#endif
