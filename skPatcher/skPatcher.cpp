#include <windows.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>

bool read_at(HANDLE h, DWORD off, void* buf, DWORD sz)
{
    DWORD br;
    SetFilePointer(h, off, nullptr, FILE_BEGIN);
    return ReadFile(h, buf, sz, &br, nullptr) && br == sz;
}

bool write_at(HANDLE h, DWORD off, const void* buf, DWORD sz)
{
    DWORD bw;
    SetFilePointer(h, off, nullptr, FILE_BEGIN);
    return WriteFile(h, buf, sz, &bw, nullptr) && bw == sz;
}

DWORD pe_offset(HANDLE h)
{
    DWORD v = 0;
    read_at(h, 0x3C, &v, sizeof(v));
    return v;
}

int find_pattern(const BYTE* data, int dataSize, const BYTE* pat, int patSize)
{
    for (int i = 0; i <= dataSize - patSize; i++)
    {
        bool ok = true;
        for (int j = 0; j < patSize; j++)
        {
            if (data[i + j] != pat[j])
            {
                ok = false;
                break;
            }
        }
        if (ok)
            return i;
    }
    return -1;
}

void strip_dos(HANDLE h)
{
    BYTE magic[2]{};
    DWORD lfanew{};

    read_at(h, 0x00, magic, 2);
    read_at(h, 0x3C, &lfanew, 4);

    BYTE zero[64]{};
    write_at(h, 0x00, zero, 64);

    write_at(h, 0x00, magic, 2);
    write_at(h, 0x3C, &lfanew, 4);

    BYTE wipe[39]{};
    write_at(h, 0x4E, wipe, sizeof(wipe));
}

void wipe_dos_stub(HANDLE h)
{
    DWORD pe = pe_offset(h);
    if (pe <= 0x4E)
        return;

    DWORD len = pe - 0x4E;
    BYTE* zero = new BYTE[len]{};
    write_at(h, 0x4E, zero, len);
    delete[] zero;
}

void strip_rich(HANDLE h)
{
    DWORD pe = pe_offset(h);
    if (!pe)
        return;

    BYTE* buf = new BYTE[pe]{};
    if (!read_at(h, 0, buf, pe))
    {
        delete[] buf;
        return;
    }

    BYTE rich[4]{ 'R','i','c','h' };
    BYTE dans[4]{ 'D','a','n','S' };

    int r = find_pattern(buf, pe, rich, 4);
    int d = find_pattern(buf, pe, dans, 4);

    if (d >= 0 && r > d)
    {
        int wipeLen = (r + 8) - d;
        BYTE* zero = new BYTE[wipeLen]{};
        write_at(h, d, zero, wipeLen);
        delete[] zero;
    }

    delete[] buf;
}

void break_checksum(HANDLE h)
{
    DWORD pe = pe_offset(h);
    if (!pe)
        return;

    DWORD fake = 0xDEADC0DE;
    write_at(h, pe + 0x58, &fake, 4);
}

int wmain()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    std::wcout << L"[ skPatcher ]\n";
    std::wcout << L"Enter path to EXE: ";

    wchar_t path[MAX_PATH]{};
    std::wcin.getline(path, MAX_PATH);

    HANDLE h = CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"Failed to open file\n";
        return 1;
    }

    strip_dos(h);
    wipe_dos_stub(h);
    strip_rich(h);
    break_checksum(h);

    CloseHandle(h);

    std::wcout << L"Patching complete\n";
    return 0;
}
