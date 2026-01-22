#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <filesystem>
#include "skCrypter.h"
#include "skSigs.h"
#include "skDebug.h"

static HANDLE GetProcessByName(const std::wstring& name)
{
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);

    if (Process32FirstW(snapshot, &process))
    {
        do
        {
            if (name == process.szExeFile)
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid)
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    return INVALID_HANDLE_VALUE;
}

int main()
{
    SetConsoleTitleA(skCrypt("DONT RENAME "your".dll!")); // type "your" dll name

    VMP0();
    VMP1();
    ENIGMA1();
    ENIGMA2();
    THEMIDA();
    skd::brk();

    std::cout << skCrypt(
        "DONT RENAME yourdllname.dll!\n"
        "Enter -insecure in csgo params\n"
        "waiting for csgo...\n"
    );

    HANDLE hProc = INVALID_HANDLE_VALUE;

    const auto path = std::filesystem::current_path();
    const auto pathStr = path.wstring() + L"\\here.dll"; // type "here" your dll name 

    while (hProc == INVALID_HANDLE_VALUE)
        hProc = GetProcessByName(L"csgo.exe");

    auto cheat = VirtualAllocEx(
        hProc,
        nullptr,
        0x2FC000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!cheat)
        std::cout << skCrypt("failed to allocate cheat!\n");

    auto arg = VirtualAllocEx(
        hProc,
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    WriteProcessMemory(
        hProc,
        arg,
        pathStr.c_str(),
        (pathStr.size() + 1) * sizeof(wchar_t),
        nullptr
    );

    auto hThread = CreateRemoteThread(
        hProc,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(
                GetModuleHandleA(skCrypt("kernel32.dll")),
                skCrypt("LoadLibraryW")
            )
            ),
        arg,
        0,
        nullptr
    );

    std::cout << skCrypt("csgo.exe found!\n");
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
