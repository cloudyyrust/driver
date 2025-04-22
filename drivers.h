#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
HWND window_handle;
HWND windowid = NULL;
uintptr_t Nunflaggedbase;
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
) 

#define READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1A2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BASE_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1A3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _RWOp
{
    INT32 ProcID;
    ULONGLONG TargetAddr;
    ULONGLONG  DataBuffer;
    ULONGLONG  DataSize;
} RWOp, * pRWOp;  // is it not here 
typedef struct _MU
{
    long x;
    long y;
    unsigned short button_flags;
};
typedef struct _BaseAddrQUR
{
    INT32 ProcID;
    ULONGLONG* TargetPtr;
} BaseAddrQUR, * pBaseAddrQUR;

namespace Driver
{
    HANDLE DriverHandle;
    INT32 ProcessID;

    inline bool Init()
    {
        // SPOOF_FUNC;
        DriverHandle = CreateFileA("\\\\.\\\\T65_VDMA", GENERIC_READ | GENERIC_WRITE, 0, 0, 3, 0x00000080, 0);
        if (!DriverHandle || (DriverHandle == INVALID_HANDLE_VALUE))
            return false;

        return true;
    }

    inline void ReadPhysicalMemory(PVOID address, PVOID buffer, DWORD size)
    {
        // SPOOF_FUNC;
        _RWOp Arguments = { 0 };
        Arguments.TargetAddr = (ULONGLONG)address;
        Arguments.DataBuffer = (ULONGLONG)buffer;
        Arguments.DataSize = size;
        Arguments.ProcID = ProcessID;
        // Arguments.Write = FALSE;

        DeviceIoControl(DriverHandle, READ_MEMORY, &Arguments, sizeof(Arguments), nullptr, NULL, NULL, NULL);
    }
    inline bool read1(const std::uintptr_t address, void* buffer, const std::size_t size)
    {
        // SPOOF_FUNC;
        if (buffer == nullptr || size == 0) {
            return false;
        }
        Driver::ReadPhysicalMemory(reinterpret_cast<PVOID>(address), buffer, static_cast<DWORD>(size));
    }
    inline uintptr_t GetBase()
    {   //This resets the cache used for translation/CR3
        uintptr_t image_address = { NULL };
        _BaseAddrQUR Arguments = { NULL };
        Arguments.ProcID = ProcessID;
        Arguments.TargetPtr = (ULONGLONG*)&image_address;
        DeviceIoControl(DriverHandle, BASE_ADDRESS, &Arguments, sizeof(Arguments), nullptr, NULL, NULL, NULL);
        return image_address;
    }

    inline INT32 FindProcess(LPCTSTR process_name)
    {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name))
                {
                    CloseHandle(hsnap);
                    ProcessID = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);
        return ProcessID;
    }
}

template <typename T>
inline T read(uint64_t address)
{
    //SPOOF_FUNC;
    T buffer{ };
    Driver::ReadPhysicalMemory((PVOID)address, &buffer, sizeof(T));
    return buffer;
}


bool is_valid(const uint64_t adress)
{
    if (adress <= 0x400000 || adress == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(adress) == nullptr || adress >
        0x7FFFFFFFFFFFFFFF) {
        return false;
    }
    return true;
}