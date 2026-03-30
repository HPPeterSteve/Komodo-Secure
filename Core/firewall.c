#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdbool.h>

// Forçar link das bibliotecas necessárias
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

/**
 * Komodo-Secure: Firewall Bridge (WFP)
 * Versão com GUIDs manuais para compatibilidade total com MSVC
 */

// GUIDs necessários (Copied from fwpmtypes.h)
// {C306D53A-4DE2-49da-97E4-3388E4AD078A}
static const GUID K_FWPM_LAYER_ALE_AUTH_CONNECT_V4 = 
{ 0xc306d53a, 0x4de2, 0x49da, { 0x97, 0xe4, 0x33, 0x88, 0xe4, 0xad, 0x07, 0x8a } };

// {A15147C6-0AF5-4148-B545-56B48D93444C}
static const GUID K_FWPM_LAYER_ALE_AUTH_CONNECT_V6 = 
{ 0xa15147c6, 0x0af5, 0x4148, { 0xb5, 0x45, 0x56, 0xb4, 0x8d, 0x93, 0x44, 0x4c } };

// {3571A120-0089-4b68-9A8C-311893320215}
static const GUID K_FWPM_SUBLAYER_UNIVERSAL = 
{ 0x3571a120, 0x0089, 0x4b68, { 0x9a, 0x8c, 0x31, 0x18, 0x93, 0x32, 0x02, 0x15 } };

// {D78E1E87-8644-4ea5-9437-D809EC651030}
static const GUID K_FWPM_CONDITION_ALE_APP_CONTAINER_SID = 
{ 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0x65, 0x10, 0x30 } };

bool block_network_for_sid(PSID appContainerSid) {
    if (appContainerSid == NULL) return false;

    HANDLE hEngine = NULL;
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(FWPM_SESSION0));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine) != ERROR_SUCCESS) {
        return false;
    }

    FWPM_FILTER_CONDITION0 condition;
    memset(&condition, 0, sizeof(FWPM_FILTER_CONDITION0));
    condition.fieldKey = K_FWPM_CONDITION_ALE_APP_CONTAINER_SID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_SID;
    condition.conditionValue.sid = (SID*)appContainerSid;

    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(FWPM_FILTER0));
    filter.displayData.name = (wchar_t*)L"KomodoSecureNetworkBlock";
    filter.action.type = FWP_ACTION_BLOCK;
    filter.subLayerKey = K_FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xFF;
    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;

    // IPv4
    filter.layerKey = K_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if (FwpmFilterAdd0(hEngine, &filter, NULL, NULL) != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return false;
    }

    // IPv6
    filter.layerKey = K_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if (FwpmFilterAdd0(hEngine, &filter, NULL, NULL) != ERROR_SUCCESS) {
        FwpmEngineClose0(hEngine);
        return false;
    }

    return true;
}