// ============================================================================
// wmic_shim.cpp
// ----------------------------------------------------------------------------
// Shim minimal destine a remplacer WMIC.exe UNIQUEMENT pour la commande
// specifique utilisee par GALSS (GALSVW64.EXE) :
//
//     WMIC path win32_process where NAME="GALSVW64.EXE" get Commandline
//
// Objectif : reproduire fidelement le comportement de wmic.exe pour CETTE
// commande precise, afin que GALSS continue de fonctionner sur des versions
// de Windows ou wmic.exe a ete definitivement retire (ex: 26H2).
//
// ============================================================================

#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <io.h>
#include <fcntl.h>
#include <cstdio>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static const int HEADER_TOTAL_WIDTH = 61; // "CommandLine" + 50 espaces (mesure)
static const int VALUE_TRAILING_SPACES = 2; // mesure sur l'echantillon

// Convertit une BSTR/VARIANT en std::wstring de maniere securisee.
static std::wstring VariantToWString(const VARIANT& var) {
    if (var.vt == VT_BSTR && var.bstrVal != nullptr) {
        return std::wstring(var.bstrVal, SysStringLen(var.bstrVal));
    }
    return L"";
}

// Passe une chaine en majuscules (pour comparaison insensible a la casse).
static std::wstring ToUpper(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return std::towupper(c); });
    return s;
}

// ----------------------------------------------------------------------------
// Detecte si la ligne de commande recue correspond au pattern GALSS :
//   path win32_process where NAME="XXX" get Commandline
// Retourne true + extrait le nom de process cible dans outProcessName.
// ----------------------------------------------------------------------------
static bool TryParseGalssPattern(const std::wstring& cmdLine,
                                  std::wstring& outProcessName) {
    std::wstring upper = ToUpper(cmdLine);

    // Recherche grossiere du pattern (a affiner selon variantes reelles
    // observees : espaces multiples, guillemets simples/doubles, etc.)
    size_t wherePos = upper.find(L"WHERE NAME=");
    size_t getPos   = upper.find(L"GET COMMANDLINE");
    size_t win32Pos = upper.find(L"WIN32_PROCESS");

    if (wherePos == std::wstring::npos ||
        getPos   == std::wstring::npos ||
        win32Pos == std::wstring::npos) {
        return false; // Pas notre pattern -> laisser un vrai wmic gerer (fallback)
    }

    // Extraction du nom entre guillemets apres "NAME="
    size_t quoteStart = cmdLine.find(L'"', wherePos);
    if (quoteStart == std::wstring::npos) return false;
    size_t quoteEnd = cmdLine.find(L'"', quoteStart + 1);
    if (quoteEnd == std::wstring::npos) return false;

    outProcessName = cmdLine.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
    return true;
}

// ----------------------------------------------------------------------------
// Interroge WMI (ROOT\CIMV2, Win32_Process) pour recuperer la CommandLine
// des process dont le Name correspond exactement (insensible a la casse).
// ----------------------------------------------------------------------------
static std::vector<std::wstring> QueryProcessCommandLines(const std::wstring& processName) {
    std::vector<std::wstring> results;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool comInitializedHere = SUCCEEDED(hr);

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    // Si deja initialise ailleurs, hr peut etre RPC_E_TOO_LATE : on ignore.

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                           IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return results;

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0,
                              NULL, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); return results; }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                            NULL, EOAC_NONE);

    // Construction de la requete WQL. Echappement basique des quotes.
    std::wstring safeName = processName;
    std::wstring query = L"SELECT CommandLine FROM Win32_Process WHERE Name = '" + safeName + L"'";

    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"), _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    if (SUCCEEDED(hr) && pEnumerator) {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;
        while (pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            if (SUCCEEDED(pObj->Get(L"CommandLine", 0, &vtProp, 0, 0))) {
                results.push_back(VariantToWString(vtProp));
            }
            VariantClear(&vtProp);
            pObj->Release();
        }
        pEnumerator->Release();
    }

    pSvc->Release();
    pLoc->Release();
    if (comInitializedHere) CoUninitialize();

    return results;
}

static std::wstring FormatWmicTable(const std::vector<std::wstring>& rows) {
    if (rows.empty()) {
        return L"\r\n";
    }

    const std::wstring& value = rows[0];

    std::wstring out;

    std::wstring header = L"CommandLine";
    int headerPadding = HEADER_TOTAL_WIDTH - (int)header.length();
    if (headerPadding < 0) headerPadding = 0; // securite si nom de champ change
    out += header + std::wstring(headerPadding, L' ') + L"\r\n";

    out += value + std::wstring(VALUE_TRAILING_SPACES, L' ') + L"\r\n";

    return out;
}

// ----------------------------------------------------------------------------
// Ecrit la sortie sur stdout en UTF-16LE avec BOM, en mode binaire pur
// (indispensable : sans _O_BINARY, Windows convertirait automatiquement les
// LF en CRLF et casserait notre CRLF deja explicite, doublant les retours
// chariot).
// ----------------------------------------------------------------------------
static void WriteOutput(const std::wstring& text) {
    _setmode(_fileno(stdout), _O_BINARY);

    unsigned char bom[2] = { 0xFF, 0xFE };
    fwrite(bom, 1, 2, stdout);
    fwrite(text.c_str(), sizeof(wchar_t), text.size(), stdout);
    fflush(stdout);
}

int wmain(int argc, wchar_t* argv[]) {
    // Reconstitution de la ligne de commande complete recue.
    std::wstring fullCmd;
    for (int i = 1; i < argc; i++) {
        fullCmd += argv[i];
        if (i < argc - 1) fullCmd += L" ";
    }

    std::wstring targetProcessName;
    if (TryParseGalssPattern(fullCmd, targetProcessName)) {
        auto rows = QueryProcessCommandLines(targetProcessName);
        std::wstring output = FormatWmicTable(rows);
        WriteOutput(output);
        return 0; // TODO: confirmer le vrai code de retour attendu
    }

    fwprintf(stderr, L"[wmic_shim] Commande non geree par ce shim : %s\n", fullCmd.c_str());
    return 1;
}
