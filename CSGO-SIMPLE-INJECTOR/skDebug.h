#pragma once
#include "skCrypter.h"
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#pragma intrinsic(__readfsdword)
#pragma intrinsic(__readgsqword)

namespace skd
{
    __forceinline bool q1()
    {
#ifdef _WIN64
        auto p = (PBYTE)__readgsqword(0x60);
#else
        auto p = (PBYTE)__readfsdword(0x30);
#endif
        return p[2] != 0;
    }

    __forceinline bool q2()
    {
        using f_t = BOOL(WINAPI*)(HANDLE, PBOOL);
        auto f = (f_t)GetProcAddress(
            GetModuleHandleA((char*)skCrypt("kernel32.dll")),
            (char*)skCrypt("CheckRemoteDebuggerPresent")
        );

        BOOL r = FALSE;
        if (f)
            f(GetCurrentProcess(), &r);

        return r;
    }

    __forceinline bool q3()
    {
        using n_t = NTSTATUS(NTAPI*)(
            HANDLE,
            PROCESSINFOCLASS,
            PVOID,
            ULONG,
            PULONG
            );

        auto n = (n_t)GetProcAddress(
            GetModuleHandleA((char*)skCrypt("ntdll.dll")),
            (char*)skCrypt("NtQueryInformationProcess")
        );

        if (!n)
            return false;

        ULONG v = 0;
        return n(
            GetCurrentProcess(),
            ProcessDebugPort,
            &v,
            sizeof(v),
            nullptr
        ) == 0 && v;
    }

    __forceinline bool q4()
    {
        LARGE_INTEGER f{}, s{}, e{};
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&s);

        for (volatile int i = 0; i < 0x800000; ++i) {}

        QueryPerformanceCounter(&e);
        return ((e.QuadPart - s.QuadPart) / (double)f.QuadPart) > 0.06;
    }

    __forceinline bool q5()
    {
        SetLastError(0);
        OutputDebugStringA((char*)skCrypt("sk"));
        return GetLastError() != 0;
    }

    __forceinline bool chk()
    {
        return q1() | q2() | q3() | q4() | q5();
    }

    __forceinline void brk()
    {
        if (chk())
        {
#if defined(_MSC_VER)
            __fastfail(0);
#else
            ExitProcess(0);
#endif
        }
    }
}
