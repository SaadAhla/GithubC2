#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI myGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI myGetProcAddress(HMODULE hMod, char* sProcName);
